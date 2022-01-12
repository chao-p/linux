// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memfile_notifier.c
 *
 *  Copyright (C) 2022  Intel Corporation.
 *             Chao Peng <chao.p.peng@linux.intel.com>
 */

#include <linux/memfile_notifier.h>
#include <linux/srcu.h>

DEFINE_STATIC_SRCU(srcu);

void memfile_notifier_invalidate(struct memfile_notifier_list *list,
				 pgoff_t start, pgoff_t end)
{
	struct memfile_notifier *notifier;
	int id;

	id = srcu_read_lock(&srcu);
	list_for_each_entry_srcu(notifier, &list->head, list,
				 srcu_read_lock_held(&srcu)) {
		if (notifier->ops && notifier->ops->invalidate)
			notifier->ops->invalidate(notifier, start, end);
	}
	srcu_read_unlock(&srcu, id);
}

void memfile_notifier_fallocate(struct memfile_notifier_list *list,
				pgoff_t start, pgoff_t end)
{
	struct memfile_notifier *notifier;
	int id;

	id = srcu_read_lock(&srcu);
	list_for_each_entry_srcu(notifier, &list->head, list,
				 srcu_read_lock_held(&srcu)) {
		if (notifier->ops && notifier->ops->fallocate)
			notifier->ops->fallocate(notifier, start, end);
	}
	srcu_read_unlock(&srcu, id);
}

#ifdef CONFIG_SHMEM
extern int shmem_get_memfile_notifier_info(struct inode *inode,
					struct memfile_notifier_list **list,
					struct memfile_pfn_ops **ops);
#endif

static int memfile_get_notifier_info(struct inode *inode,
				     struct memfile_notifier_list **list,
				     struct memfile_pfn_ops **ops)
{
	int ret = -EOPNOTSUPP;
#ifdef CONFIG_SHMEM
	ret = shmem_get_memfile_notifier_info(inode, list, ops);
#endif
	return ret;
}

int memfile_register_notifier(struct inode *inode,
			      struct memfile_notifier *notifier,
			      struct memfile_pfn_ops **pfn_ops)
{
	struct memfile_notifier_list *list;
	int ret;

	if (!inode || !notifier | !pfn_ops)
		return -EINVAL;

	ret = memfile_get_notifier_info(inode, &list, pfn_ops);
	if (ret)
		return ret;

	spin_lock(&list->lock);
	list_add_rcu(&notifier->list, &list->head);
	spin_unlock(&list->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(memfile_register_notifier);

void memfile_unregister_notifier(struct inode *inode,
				 struct memfile_notifier *notifier)
{
	struct memfile_notifier_list *list;

	if (!inode || !notifier)
		return;

	BUG_ON(memfile_get_notifier_info(inode, &list, NULL));

	spin_lock(&list->lock);
	list_del_rcu(&notifier->list);
	spin_unlock(&list->lock);

	synchronize_srcu(&srcu);
}
EXPORT_SYMBOL_GPL(memfile_unregister_notifier);
