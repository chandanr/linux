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

#endif /* __XFS_XCHGRANGE_H__ */
