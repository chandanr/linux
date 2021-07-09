/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_XCHGRANGE_H__
#define __XFS_XCHGRANGE_H__

struct xfs_swapext_req;
struct xfs_swapext_res;

void xfs_xchg_range_ilock(struct xfs_trans *tp, struct xfs_inode *ip1,
		struct xfs_inode *ip2);
void xfs_xchg_range_iunlock(struct xfs_inode *ip1, struct xfs_inode *ip2);

int xfs_xchg_range_estimate(const struct xfs_swapext_req *req,
		struct xfs_swapext_res *res);
int xfs_xchg_range_prep(struct file *file1, struct file *file2,
		struct file_xchg_range *fxr);

int xfs_xchg_range_grab_log_assist(struct xfs_mount *mp, bool force,
		bool *enabled);
void xfs_xchg_range_rele_log_assist(struct xfs_mount *mp);

/* Update ip1's change and mod time. */
#define XFS_XCHG_RANGE_UPD_CMTIME1	(1 << 0)

/* Update ip2's change and mod time. */
#define XFS_XCHG_RANGE_UPD_CMTIME2	(1 << 1)

int xfs_xchg_range(struct xfs_inode *ip1, struct xfs_inode *ip2,
		const struct file_xchg_range *fxr, unsigned int xchg_flags);

#endif /* __XFS_XCHGRANGE_H__ */
