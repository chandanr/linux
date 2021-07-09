/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef	__XFS_SWAPEXT_ITEM_H__
#define	__XFS_SWAPEXT_ITEM_H__

/*
 * The extent swapping intent item help us perform atomic extent swaps between
 * two inode forks.  It does this by tracking the range of logical offsets that
 * still need to be swapped, and relogs as progress happens.
 *
 * *I items should be recorded in the *first* of a series of rolled
 * transactions, and the *D items should be recorded in the same transaction
 * that records the associated bmbt updates.
 *
 * Should the system crash after the commit of the first transaction but
 * before the commit of the final transaction in a series, log recovery will
 * use the redo information recorded by the intent items to replay the
 * rest of the extent swaps.
 */

/* kernel only SXI/SXD definitions */

struct xfs_mount;
struct kmem_zone;

/*
 * Max number of extents in fast allocation path.
 */
#define	XFS_SXI_MAX_FAST_EXTENTS	1

/*
 * This is the "swapext update intent" log item.  It is used to log the fact
 * that we are swapping extents between two files.  It is used in conjunction
 * with the "swapext update done" log item described below.
 *
 * These log items follow the same rules as struct xfs_efi_log_item; see the
 * comments about that structure (in xfs_extfree_item.h) for more details.
 */
struct xfs_sxi_log_item {
	struct xfs_log_item		sxi_item;
	atomic_t			sxi_refcount;
	struct xfs_sxi_log_format	sxi_format;
};

/*
 * This is the "swapext update done" log item.  It is used to log the fact that
 * some extent swapping mentioned in an earlier sxi item have been performed.
 */
struct xfs_sxd_log_item {
	struct xfs_log_item		sxd_item;
	struct xfs_sxi_log_item		*sxd_intent_log_item;
	struct xfs_sxd_log_format	sxd_format;
};

extern struct kmem_zone	*xfs_sxi_zone;
extern struct kmem_zone	*xfs_sxd_zone;

#endif	/* __XFS_SWAPEXT_ITEM_H__ */
