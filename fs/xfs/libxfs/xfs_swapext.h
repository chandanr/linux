/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_SWAPEXT_H_
#define __XFS_SWAPEXT_H_ 1

/*
 * In-core information about an extent swap request between ranges of two
 * inodes.
 */
struct xfs_swapext_intent {
	/* List of other incore deferred work. */
	struct list_head	sxi_list;

	/* The two inodes we're swapping. */
	union {
		struct xfs_inode *sxi_ip1;
		xfs_ino_t	sxi_ino1;
	};
	union {
		struct xfs_inode *sxi_ip2;
		xfs_ino_t	sxi_ino2;
	};

	/* File offset range information. */
	xfs_fileoff_t		sxi_startoff1;
	xfs_fileoff_t		sxi_startoff2;
	xfs_filblks_t		sxi_blockcount;
	uint64_t		sxi_flags;

	/* Set these file sizes after the operation, unless negative. */
	xfs_fsize_t		sxi_isize1;
	xfs_fsize_t		sxi_isize2;
};

/* Set the sizes of both files after the operation. */
#define XFS_SWAPEXT_SET_SIZES		(1U << 0)

/* Do not swap any part of the range where file1's mapping is a hole. */
#define XFS_SWAPEXT_SKIP_FILE1_HOLES	(1U << 1)

/* Try to convert inode2's fork to local format, if possible. */
#define XFS_SWAPEXT_INO2_SHORTFORM	(1U << 2)

/* Parameters for a swapext request. */
struct xfs_swapext_req {
	struct xfs_inode	*ip1;
	struct xfs_inode	*ip2;
	xfs_fileoff_t		startoff1;
	xfs_fileoff_t		startoff2;
	xfs_filblks_t		blockcount;
	int			whichfork;
	unsigned int		flags;
};

/* Estimated resource requirements for a swapext operation. */
struct xfs_swapext_res {
	xfs_filblks_t		ip1_bcount;
	xfs_filblks_t		ip2_bcount;
	xfs_filblks_t		ip1_rtbcount;
	xfs_filblks_t		ip2_rtbcount;
	unsigned long long	resblks;
	unsigned int		nr_exchanges;
};

bool xfs_swapext_has_more_work(struct xfs_swapext_intent *sxi);

unsigned int xfs_swapext_reflink_prep(const struct xfs_swapext_req *req);
void xfs_swapext_reflink_finish(struct xfs_trans *tp,
		const struct xfs_swapext_req *req, unsigned int reflink_state);

int xfs_swapext_estimate_overhead(const struct xfs_swapext_req *req,
		struct xfs_swapext_res *res);
int xfs_swapext_estimate(const struct xfs_swapext_req *req,
		struct xfs_swapext_res *res);

void xfs_swapext_reschedule(struct xfs_trans *tpp,
		const struct xfs_swapext_intent *sxi_state);
int xfs_swapext_finish_one(struct xfs_trans *tp,
		struct xfs_swapext_intent *sxi_state);

int xfs_swapext_check_extents(struct xfs_mount *mp,
		const struct xfs_swapext_req *req);
bool xfs_swapext_need_rt_conversion(struct xfs_inode *ip);

int xfs_swapext(struct xfs_trans **tpp, const struct xfs_swapext_req *req);

#endif /* __XFS_SWAPEXT_H_ */
