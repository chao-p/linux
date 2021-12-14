// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>

#include "capabilities.h"
#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "tdx.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * workaround to compile.
 * TODO: once the TDX module initiation code in x86 host is merged, remove this.
 * The function returns struct tdsysinfo_struct from TDX module provides which
 * is the system wide information about the TDX module.
 * Return NULL if the TDX module is not ready for KVM to use for TDX VM guest
 * life cycle.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}
#endif

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __read_mostly;
static u32 tdx_nr_keyids __read_mostly;
static u32 tdx_seam_keyid __read_mostly;

static void __init tdx_keyids_init(void)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, tdx_nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	tdx_keyids_start = nr_mktme_ids + 1;
	tdx_seam_keyid = tdx_keyids_start;
}

/* TDX KeyID pool */
static DEFINE_IDA(tdx_keyid_pool);

static int tdx_keyid_alloc(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_TDX))
		return -EINVAL;

	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 1,
			       GFP_KERNEL);
}

static void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}

/* Capabilities of KVM + TDX-SEAM. */
struct tdx_capabilities tdx_caps;

static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr.added;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid >= 0;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

void tdx_hardware_enable(void)
{
}

void tdx_hardware_disable(void)
{
}

static void tdx_clear_page(unsigned long page)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	unsigned long i;

	/* Zeroing the page is only necessary for systems with MKTME-i. */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B))
		return;

	for (i = 0; i < 4096; i += 64)
		/* MOVDIR64B [rdx], es:rdi */
		asm (".byte 0x66, 0x0f, 0x38, 0xf8, 0x3a"
		     : : "d" (zero_page), "D" (page + i) : "memory");
}

static int __tdx_reclaim_page(unsigned long va, hpa_t pa, bool do_wb, u16 hkid)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_phymem_page_reclaim(pa, &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &ex_ret);
		return -EIO;
	}

	if (do_wb) {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va);
	return 0;
}

static int tdx_reclaim_page(unsigned long va, hpa_t pa)
{
	return __tdx_reclaim_page(va, pa, false, 0);
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static void tdx_add_td_page(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		if (tdx_reclaim_page(page->va, page->pa))
			return;

		page->added = false;
	}
	free_page(page->va);
}

void tdx_vm_teardown(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_reclaimid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_RECLAIMID, err, NULL);
		return;
	}

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		return;
	}

free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);
	kfree(kvm_tdx->tdcs);

	if (kvm_tdx->tdr.added &&
		__tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, true,
				tdx_seam_keyid))
		return;

	free_page(kvm_tdx->tdr.va);
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	hpa_t *tdr_p = param;
	int cpu, cur_pkg;
	u64 err;

	cpu = raw_smp_processor_id();
	cur_pkg = topology_physical_package_id(cpu);

	mutex_lock(&tdx_mng_key_config_lock[cur_pkg]);
	do {
		err = tdh_mng_key_config(*tdr_p);
	} while (err == TDX_KEY_GENERATION_FAILED);
	mutex_unlock(&tdx_mng_key_config_lock[cur_pkg]);

	/*
	 * TDH.MNG.KEY.CONFIG is per CPU package operation.  Other CPU on the
	 * same package did it for us.
	 */
	if (err == TDX_KEY_CONFIGURED)
		err = 0;

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret, i;
	u64 err;

	/*
	 * To generate EPT violation to inject #VE instead of EPT MISCONFIG,
	 * set RWX=0.
	 */
	kvm_mmu_set_mmio_spte_mask(kvm, 0, VMX_EPT_RWX_MASK, 0);

	/* TODO: Enable 2mb and 1gb large page support. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	/* vCPUs can't be created until after KVM_TDX_INIT_VM. */
	kvm->max_vcpus = 0;

	kvm_tdx->hkid = tdx_keyid_alloc();
	if (kvm_tdx->hkid < 0)
		return -EBUSY;
	if (WARN_ON_ONCE(kvm_tdx->hkid >> 16)) {
		ret = -EIO;
		goto free_hkid;
	}

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
	}

	ret = -EIO;
	mutex_lock(&tdx_lock);
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		goto free_tdcs;
	}
	tdx_add_td_page(&kvm_tdx->tdr);

	/*
	 * TODO: optimize to invoke the callback only once per CPU package
	 * instead of all CPUS because TDH.MNG.KEY.CONFIG is per CPU package
	 * operation.
	 *
	 * Invoke callback one-by-one to avoid contention because
	 * TDH.MNG.KEY.CONFIG competes for TDR lock.
	 */
	for_each_online_cpu(i) {
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				&kvm_tdx->tdr.pa, 1);
		if (ret)
			break;
	}
	if (ret)
		goto teardown;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr.pa, kvm_tdx->tdcs[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			goto teardown;
		}
		tdx_add_td_page(&kvm_tdx->tdcs[i]);
	}

	/*
	 * Note, TDH_MNG_INIT cannot be invoked here.  TDH_MNG_INIT requires a dedicated
	 * ioctl() to define the configure CPUID values for the TD.
	 */
	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	tdx_vm_teardown(kvm);
	tdx_vm_free(kvm);
	return ret;

free_tdcs:
	/* @i points at the TDCS page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(kvm_tdx->tdcs[i].va);
	kfree(kvm_tdx->tdcs);
free_tdr:
	free_page(kvm_tdx->tdr.va);
free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	return ret;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret, i;

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	tdx->tdvpx = kcalloc(tdx_caps.tdvpx_nr_pages, sizeof(*tdx->tdvpx),
			GFP_KERNEL_ACCOUNT);
	if (!tdx->tdvpx) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	vcpu->arch.mcg_cap = 0;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);
	kfree(tdx->tdvpx);
free_tdvpr:
	free_page(tdx->tdvpr.va);

	return ret;
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
		tdx_reclaim_td_page(&tdx->tdvpx[i]);
	kfree(tdx->tdvpx);
	tdx_reclaim_td_page(&tdx->tdvpr);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	/* TDX doesn't support INIT event. */
	if (WARN_ON(init_event))
		goto td_bugged;
	/* TDX supports only X2APIC enabled. */
	if (WARN_ON(!vcpu->arch.apic))
		goto td_bugged;
	if (WARN_ON(is_td_vcpu_created(tdx)))
		goto td_bugged;

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_add_td_page(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_add_td_page(&tdx->tdvpx[i]);
	}

	if (!vcpu->arch.cpuid_entries) {
		/*
		 * On cpu creation, cpuid entry is blank.  Forcibly enable
		 * X2APIC feature to allow X2APIC.
		 */
		struct kvm_cpuid_entry2 *e;
		e = kvmalloc_array(1, sizeof(*e), GFP_KERNEL_ACCOUNT);
		*e  = (struct kvm_cpuid_entry2) {
			.function = 1,	/* Features for X2APIC */
			.index = 0,
			.eax = 0,
			.ebx = 0,
			.ecx = 1ULL << 21,	/* X2APIC */
			.edx = 0,
		};
		vcpu->arch.cpuid_entries = e;
		vcpu->arch.cpuid_nent = 1;
	}
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa)
{
	struct tdx_ex_ret ex_ret;
	u64 err;
	int i;

	for (i = 0; i < PAGE_SIZE; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr.pa, gpa + i, &ex_ret);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &ex_ret);
			break;
		}
	}
}

static void tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn << PAGE_SHIFT;
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	hpa_t source_pa;
	u64 err;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) || kvm_is_reserved_pfn(pfn)))
		return;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	/* Pin the page, KVM doesn't yet support page migration. */
	get_page(pfn_to_page(pfn));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (is_td_finalized(kvm_tdx)) {
		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, hpa, &ex_ret);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &ex_ret);
		return;
	}

	WARN_ON(kvm_tdx->source_pa == INVALID_PAGE);
	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;

	err = tdh_mem_page_add(kvm_tdx->tdr.pa, gpa, hpa, source_pa, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &ex_ret);
	else if ((kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION))
		tdx_measure_page(kvm_tdx, gpa);

	kvm_tdx->source_pa = INVALID_PAGE;
}

static void tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				       kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = pfn << PAGE_SHIFT;
	hpa_t hpa_with_hkid;
	struct tdx_ex_ret ex_ret;
	u64 err;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	if (is_hkid_assigned(kvm_tdx)) {
		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &ex_ret);
			return;
		}

		hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
		err = tdh_phymem_page_wbinvd(hpa_with_hkid);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return;
		}
	} else if (tdx_reclaim_page((unsigned long)__va(hpa), hpa)) {
		return;
	}

	put_page(pfn_to_page(pfn));
}

static int tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *sept_page)
{
	/*
	 * level is the level of spet_page to be added.  The level of its
	 * parent's PTE entry is sp_level + 1.
	 */
	enum pg_level parent_pte_level = level + 1;
	int tdx_level = pg_level_to_tdx_sept_level(parent_pte_level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = __pa(sept_page);
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &ex_ret);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &ex_ret);
		return -EIO;
	}

	return 0;
}

static void tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn, enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &ex_ret);
}

static void tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn, enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_mem_range_unblock(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_UNBLOCK, err, &ex_ret);
}

static int tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				    void *sept_page)
{
	/*
	 * free_private_sp() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 */
	if (KVM_BUG_ON(is_hkid_assigned(to_kvm_tdx(kvm)), kvm))
		return -EINVAL;

	return tdx_reclaim_page((unsigned long)sept_page, __pa(sept_page));
}

static int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx;
	u64 err;

	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (!is_hkid_assigned(kvm_tdx))
		return 0;

	kvm_tdx->tdh_mem_track = true;

	kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH);

	if (is_hkid_assigned(kvm_tdx) && is_td_finalized(kvm_tdx)) {
		err = tdh_mem_track(to_kvm_tdx(kvm)->tdr.pa);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_TRACK, err, NULL);
	}

	WRITE_ONCE(kvm_tdx->tdh_mem_track, false);

	return 0;
}

int tdx_dev_ioctl(void __user *argp)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities caps;
	struct kvm_tdx_cmd cmd;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_CAPABILITIES)
		return -EINVAL;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdx_caps.nr_cpuid_configs)
		return -E2BIG;
	caps.nr_cpuid_configs = tdx_caps.nr_cpuid_configs;

	if (copy_to_user(user_caps->cpuid_configs, &tdx_caps.cpuid_configs,
			 tdx_caps.nr_cpuid_configs * sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

	caps.attrs_fixed0 = tdx_caps.attrs_fixed0;
	caps.attrs_fixed1 = tdx_caps.attrs_fixed1;
	caps.xfam_fixed0 = tdx_caps.xfam_fixed0;
	caps.xfam_fixed1 = tdx_caps.xfam_fixed1;

	if (copy_to_user((void __user *)cmd.data, &caps, sizeof(caps)))
		return -EFAULT;

	return 0;
}

/*
 * TDX-SEAM definitions for fixed{0,1} are inverted relative to VMX.  The TDX
 * definitions are sane, the VMX definitions are backwards.
 *
 * if fixed0[i] == 0: val[i] must be 0
 * if fixed1[i] == 1: val[i] must be 1
 */
static inline bool tdx_fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed0) | fixed1) == val;
}

static struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(struct kvm_tdx *kvm_tdx,
						u32 function, u32 index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < kvm_tdx->cpuid_nent; i++) {
		e = &kvm_tdx->cpuid_entries[i];

		if (e->function == function && (e->index == index ||
		    !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_cpuid_config *config;
	struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	u32 guest_tsc_khz;
	int max_pa;
	int i;

	/* init_vm->reserved must be zero */
	if (find_first_bit((unsigned long *)init_vm->reserved,
			   sizeof(init_vm->reserved) * 8) !=
	    sizeof(init_vm->reserved) * 8)
		return -EINVAL;

	td_params->attributes = init_vm->attributes;
	td_params->max_vcpus = init_vm->max_vcpus;

	/* TODO: Enforce consistent CPUID features for all vCPUs. */
	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		config = &tdx_caps.cpuid_configs[i];

		entry = tdx_find_cpuid_entry(kvm_tdx, config->leaf,
					     config->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Non-configurable bits must be '0', even if they are fixed to
		 * '1' by TDX-SEAM, i.e. mask off non-configurable bits.
		 */
		value = &td_params->cpuid_values[i];
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= supported_xcr0;

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;
	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &= (supported_xss | XFEATURE_MASK_PT);

	max_pa = 36;
	entry = tdx_find_cpuid_entry(kvm_tdx, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;

	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	if (!tdx_fixed_bits_valid(td_params->attributes,
				  tdx_caps.attrs_fixed0,
				  tdx_caps.attrs_fixed1))
		return -EINVAL;

	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		pr_warn("TD doesn't support perfmon. KVM needs to save/restore "
			"host perf registers properly.\n");
		return -EOPNOTSUPP;
	}

	/* Setup td_params.xfam */
	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (!tdx_fixed_bits_valid(td_params->xfam,
				  tdx_caps.xfam_fixed0,
				  tdx_caps.xfam_fixed1))
		return -EINVAL;

	if (td_params->xfam & TDX_TD_XFAM_LBR) {
		pr_warn("TD doesn't support LBR. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	if (td_params->xfam & TDX_TD_XFAM_AMX) {
		pr_warn("TD doesn't support AMX. KVM needs to save/restore "
			"IA32_XFD, IA32_XFD_ERR properly.\n");
		return -EOPNOTSUPP;
	}

	if (init_vm->tsc_khz)
		guest_tsc_khz = init_vm->tsc_khz;
	else
		guest_tsc_khz = kvm->arch.initial_tsc_khz;

	if (guest_tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
	    guest_tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ) {
		pr_warn_ratelimited("Illegal TD TSC %d Khz, it must be between [%d, %d] Khz\n",
		guest_tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ, TDX_MAX_TSC_FREQUENCY_KHZ);
		return -EINVAL;
	}

	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(guest_tsc_khz);
	if (TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency) != guest_tsc_khz) {
		pr_warn_ratelimited("TD TSC %d Khz not a multiple of 25Mhz\n", guest_tsc_khz);
		if (init_vm->tsc_khz)
			return -EINVAL;
	}

	BUILD_BUG_ON(sizeof(td_params->mrconfigid) !=
		     sizeof(init_vm->mrconfigid));
	memcpy(td_params->mrconfigid, init_vm->mrconfigid,
	       sizeof(td_params->mrconfigid));
	BUILD_BUG_ON(sizeof(td_params->mrowner) !=
		     sizeof(init_vm->mrowner));
	memcpy(td_params->mrowner, init_vm->mrowner, sizeof(td_params->mrowner));
	BUILD_BUG_ON(sizeof(td_params->mrownerconfig) !=
		     sizeof(init_vm->mrownerconfig));
	memcpy(td_params->mrownerconfig, init_vm->mrownerconfig,
	       sizeof(td_params->mrownerconfig));

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_cpuid2 __user *user_cpuid;
	struct kvm_tdx_init_vm init_vm;
	struct td_params *td_params;
	struct tdx_ex_ret ex_ret;
	struct kvm_cpuid2 cpuid;
	int ret;
	u64 err;

	BUILD_BUG_ON(sizeof(init_vm) != 512);

	if (is_td_initialized(kvm))
		return -EINVAL;

	if (cmd->metadata)
		return -EINVAL;

	if (copy_from_user(&init_vm, (void __user *)cmd->data, sizeof(init_vm)))
		return -EFAULT;

	if (init_vm.max_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	user_cpuid = (void *)init_vm.cpuid;
	if (copy_from_user(&cpuid, user_cpuid, sizeof(cpuid)))
		return -EFAULT;

	if (cpuid.nent > KVM_MAX_CPUID_ENTRIES)
		return -E2BIG;

	if (copy_from_user(&kvm_tdx->cpuid_entries, user_cpuid->entries,
			   cpuid.nent * sizeof(struct kvm_cpuid_entry2)))
		return -EFAULT;

	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		return -ENOMEM;

	kvm_tdx->cpuid_nent = cpuid.nent;

	ret = setup_tdparams(kvm, td_params, &init_vm);
	if (ret)
		goto free_tdparams;

	err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_INIT, err, &ex_ret);
		ret = -EIO;
		goto free_tdparams;
	}

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm->max_vcpus = td_params->max_vcpus;
	kvm->arch.initial_tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = BIT_ULL(51) >> PAGE_SHIFT;
	else
		kvm->arch.gfn_shared_mask = BIT_ULL(47) >> PAGE_SHIFT;

free_tdparams:
	kfree(td_params);
	if (ret)
		kvm_tdx->cpuid_nent = 0;
	return ret;
}

static inline bool tdx_is_private_gpa(struct kvm *kvm, gpa_t gpa)
{
	return !((gpa >> PAGE_SHIFT) & kvm->arch.gfn_shared_mask);
}

#define TDX_SEPT_PFERR (PFERR_WRITE_MASK | PFERR_USER_MASK)

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct kvm_vcpu *vcpu;
	struct page *page;
	kvm_pfn_t pfn;
	int idx, ret = 0;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	if (cmd->metadata & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE))
		return -EINVAL;
	if (!IS_ALIGNED(region.gpa, PAGE_SIZE))
		return -EINVAL;
	if (!region.nr_pages)
		return -EINVAL;
	if (region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa)
		return -EINVAL;
	if (!tdx_is_private_gpa(kvm, region.gpa))
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	vcpu_load(vcpu);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);

	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();


		/* Pin the source page. */
		ret = get_user_pages_fast(region.source_addr, 1, 0, &page);
		if (ret < 0)
			break;
		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		kvm_tdx->source_pa = pfn_to_hpa(page_to_pfn(page)) |
				     (cmd->metadata & KVM_TDX_MEASURE_MEMORY_REGION);

		pfn = kvm_mmu_map_tdp_page(vcpu, region.gpa, TDX_SEPT_PFERR,
					   PG_LEVEL_4K);
		if (is_error_noslot_pfn(pfn) || kvm->vm_bugged)
			ret = -EFAULT;
		else
			ret = 0;

		put_page(page);
		if (ret)
			break;

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_td_initialized(kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
		return -EIO;
	}

	kvm_tdx->finalized = true;
	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		r = tdx_init_mem_region(kvm, &tdx_cmd);
		break;
	case KVM_TDX_FINALIZE_VM:
		r = tdx_td_finalizemr(kvm);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	u64 err;

	if (tdx->initialized)
		return -EINVAL;

	if (!is_td_initialized(vcpu->kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	err = tdh_vp_init(tdx->tdvpr.pa, cmd.data);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		return -EIO;
	}

	tdx->initialized = true;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

	if (vcpu->kvm->arch.bus_lock_detection_enabled)
		td_vmcs_setbit32(tdx,
				 SECONDARY_VM_EXEC_CONTROL,
				 SECONDARY_EXEC_BUS_LOCK_DETECTION);

	return 0;
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int i, max_pkgs;
	u32 max_pa;
	const struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (tdsysinfo == NULL) {
		WARN_ON_ONCE(cpu_feature_enabled(X86_FEATURE_TDX));
		return -ENODEV;
	}

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	tdx_keyids_init();

	tdx_caps.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	tdx_caps.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;

	tdx_caps.attrs_fixed0 = tdsysinfo->attributes_fixed0;
	tdx_caps.attrs_fixed1 = tdsysinfo->attributes_fixed1;
	tdx_caps.xfam_fixed0 =	tdsysinfo->xfam_fixed0;
	tdx_caps.xfam_fixed1 = tdsysinfo->xfam_fixed1;

	tdx_caps.nr_cpuid_configs = tdsysinfo->num_cpuid_config;
	if (tdx_caps.nr_cpuid_configs > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
		    tdsysinfo->num_cpuid_config * sizeof(struct tdx_cpuid_config)))
		return -EIO;

	x86_ops->tlb_remote_flush = tdx_sept_tlb_remote_flush;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->drop_private_spte = tdx_sept_drop_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;
	x86_ops->unzap_private_spte = tdx_sept_unzap_private_spte;
	x86_ops->link_private_sp = tdx_sept_link_private_sp;
	x86_ops->free_private_sp = tdx_sept_free_private_sp;

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock) {
		kfree(tdx_mng_key_config_lock);
		return -ENOMEM;
	}
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	return 0;
}

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}
