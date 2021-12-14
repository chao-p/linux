// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size) {}
int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }
void tdx_hardware_enable(void) {}
void tdx_hardware_disable(void) {}

int tdx_dev_ioctl(void __user *argp) { return -EOPNOTSUPP; }
int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return -EOPNOTSUPP; }
