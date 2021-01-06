// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __XFS_SCRUB_REPAIR_H__
#define __XFS_SCRUB_REPAIR_H__

#include "xfs_btree.h"
#include "xfs_quota_defs.h"
#include "scrub/bitmap.h"

union xfs_btree_ptr;

static inline int xrep_notsupported(struct xfs_scrub *sc)
{
	return -EOPNOTSUPP;
}

#ifdef CONFIG_XFS_ONLINE_REPAIR

/* Repair helpers */

int xrep_attempt(struct xfs_scrub *sc);
void xrep_failure(struct xfs_mount *mp);
int xrep_roll_ag_trans(struct xfs_scrub *sc);
int xrep_roll_trans(struct xfs_scrub *sc);
bool xrep_ag_has_space(struct xfs_perag *pag, xfs_extlen_t nr_blocks,
		enum xfs_ag_resv_type type);
xfs_extlen_t xrep_calc_ag_resblks(struct xfs_scrub *sc);
int xrep_alloc_ag_block(struct xfs_scrub *sc,
		const struct xfs_owner_info *oinfo, xfs_fsblock_t *fsbno,
		enum xfs_ag_resv_type resv);
int xrep_init_btblock(struct xfs_scrub *sc, xfs_fsblock_t fsb,
		struct xfs_buf **bpp, xfs_btnum_t btnum,
		const struct xfs_buf_ops *ops);

struct xbitmap;

int xrep_fix_freelist(struct xfs_scrub *sc, bool can_shrink);
int xrep_reap_extents(struct xfs_scrub *sc, struct xbitmap *exlist,
		const struct xfs_owner_info *oinfo, enum xfs_ag_resv_type type);

struct xrep_find_ag_btree {
	/* in: rmap owner of the btree we're looking for */
	uint64_t			rmap_owner;

	/* in: buffer ops */
	const struct xfs_buf_ops	*buf_ops;

	/* out: the highest btree block found and the tree height */
	xfs_agblock_t			root;
	unsigned int			height;
};

int xrep_find_ag_btree_roots(struct xfs_scrub *sc, struct xfs_buf *agf_bp,
		struct xrep_find_ag_btree *btree_info, struct xfs_buf *agfl_bp);
void xrep_force_quotacheck(struct xfs_scrub *sc, xfs_dqtype_t type);
int xrep_ino_dqattach(struct xfs_scrub *sc);

/* Metadata repairers */

int xrep_probe(struct xfs_scrub *sc);
int xrep_superblock(struct xfs_scrub *sc);
int xrep_agf(struct xfs_scrub *sc);
int xrep_agfl(struct xfs_scrub *sc);
int xrep_agi(struct xfs_scrub *sc);

struct xrep_newbt_resv {
	/* Link to list of extents that we've reserved. */
	struct list_head	list;

	/* FSB of the block we reserved. */
	xfs_fsblock_t		fsbno;

	/* Length of the reservation. */
	xfs_extlen_t		len;

	/* How much of this reservation has been used. */
	xfs_extlen_t		used;
};

struct xrep_newbt {
	struct xfs_scrub	*sc;

	/* List of extents that we've reserved. */
	struct list_head	resv_list;

	/* Fake root for new btree. */
	union {
		struct xbtree_afakeroot	afake;
		struct xbtree_ifakeroot	ifake;
	};

	/* rmap owner of these blocks */
	struct xfs_owner_info	oinfo;

	/* Allocation hint */
	xfs_fsblock_t		alloc_hint;

	/* per-ag reservation type */
	enum xfs_ag_resv_type	resv;
};

void xrep_newbt_init_bare(struct xrep_newbt *xnr, struct xfs_scrub *sc);
void xrep_newbt_init_ag(struct xrep_newbt *xnr, struct xfs_scrub *sc,
		const struct xfs_owner_info *oinfo, xfs_fsblock_t alloc_hint,
		enum xfs_ag_resv_type resv);
void xrep_newbt_init_inode(struct xrep_newbt *xnr, struct xfs_scrub *sc,
		int whichfork, const struct xfs_owner_info *oinfo);
int xrep_newbt_add_blocks(struct xrep_newbt *xnr, xfs_fsblock_t fsbno,
		xfs_extlen_t len);
int xrep_newbt_alloc_blocks(struct xrep_newbt *xnr, uint64_t nr_blocks);
void xrep_newbt_destroy(struct xrep_newbt *xnr, int error);
int xrep_newbt_claim_block(struct xfs_btree_cur *cur, struct xrep_newbt *xnr,
		union xfs_btree_ptr *ptr);
void xrep_bload_estimate_slack(struct xfs_scrub *sc,
		struct xfs_btree_bload *bload);

#else

static inline int
xrep_attempt(
	struct xfs_scrub	*sc)
{
	return -EOPNOTSUPP;
}

static inline void xrep_failure(struct xfs_mount *mp) {}

static inline xfs_extlen_t
xrep_calc_ag_resblks(
	struct xfs_scrub	*sc)
{
	return 0;
}

#define xrep_probe			xrep_notsupported
#define xrep_superblock			xrep_notsupported
#define xrep_agf			xrep_notsupported
#define xrep_agfl			xrep_notsupported
#define xrep_agi			xrep_notsupported

#endif /* CONFIG_XFS_ONLINE_REPAIR */

#endif	/* __XFS_SCRUB_REPAIR_H__ */
