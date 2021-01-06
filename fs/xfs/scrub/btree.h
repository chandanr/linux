// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __XFS_SCRUB_BTREE_H__
#define __XFS_SCRUB_BTREE_H__

/* btree scrub */

/* Check for btree operation errors. */
bool xchk_btree_process_error(struct xfs_scrub *sc,
		struct xfs_btree_cur *cur, int level, int *error);

/* Check for btree xref operation errors. */
bool xchk_btree_xref_process_error(struct xfs_scrub *sc,
		struct xfs_btree_cur *cur, int level, int *error);

/* Check for btree corruption. */
void xchk_btree_set_corrupt(struct xfs_scrub *sc,
		struct xfs_btree_cur *cur, int level);

/* Check for btree xref discrepancies. */
void xchk_btree_xref_set_corrupt(struct xfs_scrub *sc,
		struct xfs_btree_cur *cur, int level);

struct xchk_btree;
typedef int (*xchk_btree_rec_fn)(
	struct xchk_btree	*bs,
	union xfs_btree_rec	*rec);

struct xchk_btree_levels {
	union xfs_btree_key		lastkey;
	bool				has_lastkey;
};

struct xchk_btree {
	/* caller-provided scrub state */
	struct xfs_scrub		*sc;
	struct xfs_btree_cur		*cur;
	xchk_btree_rec_fn		scrub_rec;
	const struct xfs_owner_info	*oinfo;
	void				*private;

	/* internal scrub state */
	union xfs_btree_rec		lastrec;
	struct list_head		to_check;
	struct xchk_btree_levels	levels[];
};

static inline size_t
xchk_btree_sizeof(unsigned int levels)
{
	return sizeof(struct xchk_btree) +
				(levels * sizeof(struct xchk_btree_levels));
}

int xchk_btree(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		xchk_btree_rec_fn scrub_fn, const struct xfs_owner_info *oinfo,
		void *private);

#endif /* __XFS_SCRUB_BTREE_H__ */
