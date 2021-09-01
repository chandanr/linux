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

	/* Inodes participating in the operation. */
	struct xfs_inode	*sxi_ip1;
	struct xfs_inode	*sxi_ip2;

	/* File offset range information. */
	xfs_fileoff_t		sxi_startoff1;
	xfs_fileoff_t		sxi_startoff2;
	xfs_filblks_t		sxi_blockcount;

	/* Set these file sizes after the operation, unless negative. */
	xfs_fsize_t		sxi_isize1;
	xfs_fsize_t		sxi_isize2;

	/* XFS_SWAP_EXT_* log operation flags */
	uint64_t		sxi_flags;
};

static inline int
xfs_swapext_whichfork(const struct xfs_swapext_intent *sxi)
{
	if (sxi->sxi_flags & XFS_SWAP_EXT_ATTR_FORK)
		return XFS_ATTR_FORK;
	return XFS_DATA_FORK;
}

/* Parameters for a swapext request. */
struct xfs_swapext_req {
	/* Inodes participating in the operation. */
	struct xfs_inode	*ip1;
	struct xfs_inode	*ip2;

	/* File offset range information. */
	xfs_fileoff_t		startoff1;
	xfs_fileoff_t		startoff2;
	xfs_filblks_t		blockcount;

	/* Data or attr fork? */
	int			whichfork;

	/* XFS_SWAP_REQ_* operation flags */
	unsigned int		req_flags;
};

/* Set the file sizes when finished. */
#define XFS_SWAP_REQ_SET_SIZES		(1U << 1)

/* Do not swap any part of the range where file1's mapping is a hole. */
#define XFS_SWAP_REQ_SKIP_FILE1_HOLES	(1U << 2)

/* Try to convert inode2's fork to local format, if possible. */
#define XFS_SWAP_REQ_FILE2_CVT_SF	(1U << 3)

#define XFS_SWAP_REQ_FLAGS		(XFS_SWAP_REQ_SET_SIZES | \
					 XFS_SWAP_REQ_SKIP_FILE1_HOLES | \
					 XFS_SWAP_REQ_FILE2_CVT_SF)

#define XFS_SWAP_REQ_STRINGS \
	{ XFS_SWAP_REQ_SET_SIZES,		"SETSIZES" }, \
	{ XFS_SWAP_REQ_SKIP_FILE1_HOLES,	"SKIP_FILE1_HOLES" }, \
	{ XFS_SWAP_REQ_FILE2_CVT_SF,		"INO2_SHORTFORM" }

/* Estimated resource requirements for a swapext operation. */
struct xfs_swapext_res {
	xfs_filblks_t		ip1_bcount;
	xfs_filblks_t		ip2_bcount;
	xfs_filblks_t		ip1_rtbcount;
	xfs_filblks_t		ip2_rtbcount;
	unsigned long long	resblks;
	unsigned int		nr_exchanges;
};

unsigned int xfs_swapext_reflink_prep(const struct xfs_swapext_req *req);
void xfs_swapext_reflink_finish(struct xfs_trans *tp,
		const struct xfs_swapext_req *req, unsigned int reflink_state);

int xfs_swapext_estimate_overhead(const struct xfs_swapext_req *req,
		struct xfs_swapext_res *res);
int xfs_swapext_estimate(const struct xfs_swapext_req *req,
		struct xfs_swapext_res *res);

struct xfs_swapext_intent *xfs_swapext_init_intent(
		const struct xfs_swapext_req *req);

void xfs_swapext_schedule(struct xfs_trans *tp,
		struct xfs_swapext_intent *sxi);
int xfs_swapext_finish_one(struct xfs_trans *tp,
		struct xfs_swapext_intent *sxi);

int xfs_swapext_check_extents(struct xfs_mount *mp,
		const struct xfs_swapext_req *req);

int xfs_swapext(struct xfs_trans **tpp, const struct xfs_swapext_req *req);

#endif /* __XFS_SWAPEXT_H_ */
