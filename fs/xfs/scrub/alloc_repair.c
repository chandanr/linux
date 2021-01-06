// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_btree.h"
#include "xfs_bit.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_inode.h"
#include "xfs_refcount.h"
#include "xfs_extent_busy.h"
#include "xfs_health.h"
#include "xfs_bmap.h"
#include "xfs_ialloc.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/bitmap.h"
#include "scrub/array.h"

/*
 * Free Space Btree Repair
 * =======================
 *
 * The reverse mappings are supposed to record all space usage for the entire
 * AG.  Therefore, we can recalculate the free extents in an AG by looking for
 * gaps in the physical extents recorded in the rmapbt.  On a reflink
 * filesystem this is a little more tricky in that we have to be aware that
 * the rmap records are allowed to overlap.
 *
 * We derive which blocks belonged to the old bnobt/cntbt by recording all the
 * OWN_AG extents and subtracting out the blocks owned by all other OWN_AG
 * metadata: the rmapbt blocks visited while iterating the reverse mappings
 * and the AGFL blocks.
 *
 * Once we have both of those pieces, we can reconstruct the bnobt and cntbt
 * by blowing out the free block state and freeing all the extents that we
 * found.  This adds the requirement that we can't have any busy extents in
 * the AG because the busy code cannot handle duplicate records.
 *
 * Note that we can only rebuild both free space btrees at the same time
 * because the regular extent freeing infrastructure loads both btrees at the
 * same time.
 *
 * We use the prefix 'xrep_abt' here because we regenerate both free space
 * allocation btrees at the same time.
 */

struct xrep_abt {
	/* Blocks owned by the rmapbt or the agfl. */
	struct xbitmap		not_allocbt_blocks;

	/* All OWN_AG blocks. */
	struct xbitmap		old_allocbt_blocks;

	/*
	 * New bnobt information.  All btree block reservations are added to
	 * the reservation list in new_bnobt_info.
	 */
	struct xrep_newbt	new_bnobt_info;
	struct xfs_btree_bload	bno_bload;

	/* new cntbt information */
	struct xrep_newbt	new_cntbt_info;
	struct xfs_btree_bload	cnt_bload;

	/* Free space extents. */
	struct xfbma		*free_records;

	struct xfs_scrub	*sc;

	/* Number of non-null records in @free_records. */
	uint64_t		nr_real_records;

	/* get_record()'s position in the free space record array. */
	uint64_t		iter;

	/*
	 * Next block we anticipate seeing in the rmap records.  If the next
	 * rmap record is greater than next_bno, we have found unused space.
	 */
	xfs_agblock_t		next_bno;

	/* Number of free blocks in this AG. */
	xfs_agblock_t		nr_blocks;

	/* Longest free extent we found in the AG. */
	xfs_agblock_t		longest;
};

/* Check for any obvious conflicts in the free extent. */
STATIC int
xrep_abt_check_free_ext(
	struct xfs_scrub	*sc,
	const struct xfs_alloc_rec_incore *rec)
{
	bool			has_inodes, shared;
	int			error;

	/* Must be within the AG and not static data. */
	if (!xfs_verify_agbext(sc->mp, sc->sa.agno, rec->ar_startblock,
				rec->ar_blockcount))
		return -EFSCORRUPTED;

	/* Must not be an inode chunk. */
	error = xfs_ialloc_has_inodes_at_extent(sc->sa.ino_cur,
			rec->ar_startblock, rec->ar_blockcount, &has_inodes);
	if (error)
		return error;
	if (has_inodes)
		return -EFSCORRUPTED;

	/* Must not be shared or CoW staging. */
	if (sc->sa.refc_cur) {
		error = xfs_refcount_has_record(sc->sa.refc_cur,
				rec->ar_startblock, rec->ar_blockcount,
				&shared);
		if (error)
			return error;
		if (shared)
			return -EFSCORRUPTED;
	}

	return 0;
}

/*
 * Stash a free space record for all the space since the last bno we found
 * all the way up to @end.
 */
static int
xrep_abt_stash(
	struct xrep_abt		*ra,
	xfs_agblock_t		end)
{
	struct xfs_alloc_rec_incore arec = {
		.ar_startblock	= ra->next_bno,
		.ar_blockcount	= end - ra->next_bno,
	};
	struct xfs_scrub	*sc = ra->sc;
	int			error = 0;

	if (xchk_should_terminate(sc, &error))
		return error;

	error = xrep_abt_check_free_ext(ra->sc, &arec);
	if (error)
		return error;

	trace_xrep_abt_found(sc->mp, sc->sa.agno, &arec);

	error = xfbma_append(ra->free_records, &arec);
	if (error)
		return error;

	ra->nr_blocks += arec.ar_blockcount;
	return 0;
}

/* Record extents that aren't in use from gaps in the rmap records. */
STATIC int
xrep_abt_walk_rmap(
	struct xfs_btree_cur	*cur,
	struct xfs_rmap_irec	*rec,
	void			*priv)
{
	struct xrep_abt		*ra = priv;
	xfs_fsblock_t		fsb;
	int			error;

	/* Record all the OWN_AG blocks... */
	if (rec->rm_owner == XFS_RMAP_OWN_AG) {
		fsb = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_ag.agno,
				rec->rm_startblock);
		error = xbitmap_set(&ra->old_allocbt_blocks, fsb,
				rec->rm_blockcount);
		if (error)
			return error;
	}

	/* ...and all the rmapbt blocks... */
	error = xbitmap_set_btcur_path(&ra->not_allocbt_blocks, cur);
	if (error)
		return error;

	/* ...and all the free space. */
	if (rec->rm_startblock > ra->next_bno) {
		error = xrep_abt_stash(ra, rec->rm_startblock);
		if (error)
			return error;
	}

	/*
	 * rmap records can overlap on reflink filesystems, so project next_bno
	 * as far out into the AG space as we currently know about.
	 */
	ra->next_bno = max_t(xfs_agblock_t, ra->next_bno,
			rec->rm_startblock + rec->rm_blockcount);
	return 0;
}

/* Collect an AGFL block for the not-to-release list. */
static int
xrep_abt_walk_agfl(
	struct xfs_mount	*mp,
	xfs_agblock_t		bno,
	void			*priv)
{
	struct xrep_abt		*ra = priv;
	xfs_fsblock_t		fsb;

	fsb = XFS_AGB_TO_FSB(mp, ra->sc->sa.agno, bno);
	return xbitmap_set(&ra->not_allocbt_blocks, fsb, 1);
}

/*
 * Compare two free space extents by block number.  We want to sort by block
 * number.
 */
static int
xrep_bnobt_extent_cmp(
	const void		*a,
	const void		*b)
{
	const struct xfs_alloc_rec_incore *ap = a;
	const struct xfs_alloc_rec_incore *bp = b;

	if (ap->ar_startblock > bp->ar_startblock)
		return 1;
	else if (ap->ar_startblock < bp->ar_startblock)
		return -1;
	return 0;
}

/*
 * Compare two free space extents by length and then block number.  We want
 * to sort first in order of decreasing length and then in increasing block
 * number.
 */
static int
xrep_cntbt_extent_cmp(
	const void			*a,
	const void			*b)
{
	const struct xfs_alloc_rec_incore *ap = a;
	const struct xfs_alloc_rec_incore *bp = b;

	if (ap->ar_blockcount > bp->ar_blockcount)
		return 1;
	else if (ap->ar_blockcount < bp->ar_blockcount)
		return -1;
	return xrep_bnobt_extent_cmp(a, b);
}

/*
 * Iterate all reverse mappings to find (1) the gaps between rmap records (all
 * unowned space), (2) the OWN_AG extents (which encompass the free space
 * btrees, the rmapbt, and the agfl), (3) the rmapbt blocks, and (4) the AGFL
 * blocks.  The free space is (1) + (2) - (3) - (4).
 */
STATIC int
xrep_abt_find_freespace(
	struct xrep_abt		*ra)
{
	struct xfs_scrub	*sc = ra->sc;
	struct xfs_mount	*mp = sc->mp;
	struct xfs_agf		*agf = sc->sa.agf_bp->b_addr;
	xfs_agblock_t		agend;
	int			error;

	xbitmap_init(&ra->not_allocbt_blocks);

	xrep_ag_btcur_init(sc, &sc->sa);

	/*
	 * Iterate all the reverse mappings to find gaps in the physical
	 * mappings, all the OWN_AG blocks, and all the rmapbt extents.
	 */
	error = xfs_rmap_query_all(sc->sa.rmap_cur, xrep_abt_walk_rmap, ra);
	if (error)
		goto err;

	/* Insert a record for space between the last rmap and EOAG. */
	agend = be32_to_cpu(agf->agf_length);
	if (ra->next_bno < agend) {
		error = xrep_abt_stash(ra, agend);
		if (error)
			goto err;
	}

	/* Collect all the AGFL blocks. */
	error = xfs_agfl_walk(mp, agf, sc->sa.agfl_bp, xrep_abt_walk_agfl, ra);
	if (error)
		goto err;

	/* Compute the old bnobt/cntbt blocks. */
	xbitmap_disunion(&ra->old_allocbt_blocks, &ra->not_allocbt_blocks);

	ra->nr_real_records = xfbma_length(ra->free_records);
err:
	xchk_ag_btcur_free(&sc->sa);
	xbitmap_destroy(&ra->not_allocbt_blocks);
	return error;
}

/*
 * We're going to use the observed free space records to reserve blocks for the
 * new free space btrees, so we play an iterative game where we try to converge
 * on the number of blocks we need:
 *
 * 1. Estimate how many blocks we'll need to store the records.
 * 2. If the first free record has more blocks than we need, we're done.
 *    We will have to re-sort the records prior to building the cntbt.
 * 3. If that record has exactly the number of blocks we need, null out the
 *    record.  We're done.
 * 4. Otherwise, we still need more blocks.  Null out the record, subtract its
 *    length from the number of blocks we need, and go back to step 1.
 *
 * Fortunately, we don't have to do any transaction work to play this game, so
 * we don't have to tear down the staging cursors.
 */
STATIC int
xrep_abt_reserve_space(
	struct xrep_abt		*ra,
	struct xfs_btree_cur	*bno_cur,
	struct xfs_btree_cur	*cnt_cur,
	bool			*needs_sort)
{
	struct xfs_scrub	*sc = ra->sc;
	uint64_t		record_nr = xfbma_length(ra->free_records) - 1;
	unsigned int		allocated = 0;
	int			error = 0;

	*needs_sort = false;
	do {
		struct xfs_alloc_rec_incore arec;
		xfs_fsblock_t		fsbno;
		uint64_t		required;
		unsigned int		desired;
		unsigned int		len;

		/* Compute how many blocks we'll need. */
		error = xfs_btree_bload_compute_geometry(cnt_cur,
				&ra->cnt_bload, ra->nr_real_records);
		if (error)
			break;

		error = xfs_btree_bload_compute_geometry(bno_cur,
				&ra->bno_bload, ra->nr_real_records);
		if (error)
			break;

		/* How many btree blocks do we need to store all records? */
		required = ra->cnt_bload.nr_blocks + ra->bno_bload.nr_blocks;
		ASSERT(required < INT_MAX);

		/* If we've reserved enough blocks, we're done. */
		if (allocated >= required)
			break;

		desired = required - allocated;

		/* We need space but there's none left; bye! */
		if (ra->nr_real_records == 0) {
			error = -ENOSPC;
			break;
		}

		/* Grab the first record from the list. */
		error = xfbma_get(ra->free_records, record_nr, &arec);
		if (error)
			break;

		ASSERT(arec.ar_blockcount <= UINT_MAX);
		len = min_t(unsigned int, arec.ar_blockcount, desired);
		fsbno = XFS_AGB_TO_FSB(sc->mp, sc->sa.agno, arec.ar_startblock);
		error = xrep_newbt_add_blocks(&ra->new_bnobt_info, fsbno, len);
		if (error)
			break;
		allocated += len;
		ra->nr_blocks -= len;

		if (arec.ar_blockcount > desired) {
			/*
			 * Record has more space than we need.  The number of
			 * free records doesn't change, so shrink the free
			 * record, inform the caller that we've broken the sort
			 * order of the records, and exit.
			 */
			arec.ar_startblock += desired;
			arec.ar_blockcount -= desired;
			error = xfbma_set(ra->free_records, record_nr, &arec);
			if (error)
				break;
			*needs_sort = true;
			break;
		}

		/*
		 * We're going to use up the entire record, so nullify it and
		 * move on to the next one.  This changes the number of free
		 * records, so we must go around the loop once more to re-run
		 * _bload_init.
		 */
		error = xfbma_nullify(ra->free_records, record_nr);
		if (error)
			break;
		ra->nr_real_records--;
		record_nr--;
	} while (1);

	return error;
}

/*
 * Deal with all the space we reserved.  Blocks that were allocated for the
 * free space btrees need to have a (deferred) rmap added for the OWN_AG
 * allocation, and blocks that didn't get used can be freed via the usual
 * (deferred) means.
 */
STATIC void
xrep_abt_dispose_reservations(
	struct xrep_abt		*ra,
	int			error)
{
	struct xrep_newbt_resv	*resv, *n;
	struct xfs_scrub	*sc = ra->sc;

	if (error)
		goto junkit;

	for_each_xrep_newbt_reservation(&ra->new_bnobt_info, resv, n) {
		/* Add a deferred rmap for each extent we used. */
		if (resv->used > 0)
			xfs_rmap_alloc_extent(sc->tp,
					XFS_FSB_TO_AGNO(sc->mp, resv->fsbno),
					XFS_FSB_TO_AGBNO(sc->mp, resv->fsbno),
					resv->used, XFS_RMAP_OWN_AG);

		/*
		 * Add a deferred free for each block we didn't use and now
		 * have to add to the free space since the new btrees are
		 * online.
		 */
		if (resv->used < resv->len)
			__xfs_bmap_add_free(sc->tp, resv->fsbno + resv->used,
					resv->len - resv->used, NULL, true);
	}

junkit:
	for_each_xrep_newbt_reservation(&ra->new_bnobt_info, resv, n) {
		list_del(&resv->list);
		kmem_free(resv);
	}

	xrep_newbt_destroy(&ra->new_bnobt_info, error);
	xrep_newbt_destroy(&ra->new_cntbt_info, error);
}

/* Retrieve free space data for bulk load. */
STATIC int
xrep_abt_get_record(
	struct xfs_btree_cur		*cur,
	void				*priv)
{
	struct xfs_alloc_rec_incore	*arec = &cur->bc_rec.a;
	struct xrep_abt			*ra = priv;
	int				error;

	error = xfbma_iter_get(ra->free_records, &ra->iter, arec);
	if (error)
		return error;

	ra->longest = max(ra->longest, arec->ar_blockcount);
	return 0;
}

/* Feed one of the new btree blocks to the bulk loader. */
STATIC int
xrep_abt_claim_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	void			*priv)
{
	struct xrep_abt		*ra = priv;

	return xrep_newbt_claim_block(cur, &ra->new_bnobt_info, ptr);
}

/*
 * Reset the AGF counters to reflect the free space btrees that we just
 * rebuilt, then reinitialize the per-AG data.
 */
STATIC int
xrep_abt_reset_counters(
	struct xrep_abt		*ra,
	unsigned int		freesp_btreeblks)
{
	struct xfs_scrub	*sc = ra->sc;
	struct xfs_perag	*pag = sc->sa.pag;
	struct xfs_agf		*agf = sc->sa.agf_bp->b_addr;
	struct xfs_buf		*bp;

	/*
	 * Mark the pagf information stale and use the accessor function to
	 * forcibly reload it from the values we just logged.  We still own the
	 * AGF buffer so we can safely ignore bp.
	 */
	ASSERT(pag->pagf_init);
	pag->pagf_init = 0;

	agf->agf_btreeblks = cpu_to_be32(freesp_btreeblks +
				(be32_to_cpu(agf->agf_rmap_blocks) - 1));
	agf->agf_freeblks = cpu_to_be32(ra->nr_blocks);
	agf->agf_longest = cpu_to_be32(ra->longest);
	xfs_alloc_log_agf(sc->tp, sc->sa.agf_bp, XFS_AGF_BTREEBLKS |
						 XFS_AGF_LONGEST |
						 XFS_AGF_FREEBLKS);

	return xfs_alloc_read_agf(sc->mp, sc->tp, sc->sa.agno, 0, &bp);
}

static void
xrep_abt_init_bload(
	struct xrep_abt		*ra,
	struct xfs_btree_bload	*bload)
{
	bload->get_record = xrep_abt_get_record;
	bload->claim_block = xrep_abt_claim_block;

	xrep_bload_estimate_slack(ra->sc, bload);
}

/*
 * Use the collected free space information to stage new free space btrees.
 * If this is successful we'll return with the new btree root
 * information logged to the repair transaction but not yet committed.
 */
STATIC int
xrep_abt_build_new_trees(
	struct xrep_abt		*ra)
{
	struct xfs_scrub	*sc = ra->sc;
	struct xfs_btree_cur	*bno_cur;
	struct xfs_btree_cur	*cnt_cur;
	bool			needs_sort;
	int			error;

	xrep_abt_init_bload(ra, &ra->bno_bload);
	xrep_abt_init_bload(ra, &ra->cnt_bload);

	/*
	 * Sort the free extents by length so that we can set up the free space
	 * btrees in as few extents as possible.  This reduces the amount of
	 * deferred rmap / free work we have to do at the end.
	 */
	error = xfbma_sort(ra->free_records, xrep_cntbt_extent_cmp);
	if (error)
		return error;

	/*
	 * Prepare to construct the new btree by reserving disk space for the
	 * new btree and setting up all the accounting information we'll need
	 * to root the new btree while it's under construction and before we
	 * attach it to the AG header.
	 */
	xrep_newbt_init_bare(&ra->new_bnobt_info, sc);
	xrep_newbt_init_bare(&ra->new_cntbt_info, sc);

	/* Allocate cursors for the staged btrees. */
	bno_cur = xfs_allocbt_stage_cursor(sc->mp, &ra->new_bnobt_info.afake,
			sc->sa.agno, XFS_BTNUM_BNO);
	cnt_cur = xfs_allocbt_stage_cursor(sc->mp, &ra->new_cntbt_info.afake,
			sc->sa.agno, XFS_BTNUM_CNT);

	/* Reserve the space we'll need for the new btrees. */
	error = xrep_abt_reserve_space(ra, bno_cur, cnt_cur, &needs_sort);
	if (error)
		goto out_cur;

	/*
	 * If we need to re-sort the free extents by length, do so so that we
	 * can put the records into the cntbt in the correct order.
	 */
	if (needs_sort) {
		error = xfbma_sort(ra->free_records, xrep_cntbt_extent_cmp);
		if (error)
			goto out_cur;
	}

	/* Load the free space by length tree. */
	ra->iter = 0;
	ra->longest = 0;
	error = xfs_btree_bload(cnt_cur, &ra->cnt_bload, ra);
	if (error)
		goto out_cur;

	/* Re-sort the free extents by block number so so that we can put the
	 * records into the bnobt in the correct order.
	 */
	error = xfbma_sort(ra->free_records, xrep_bnobt_extent_cmp);
	if (error)
		goto out_cur;

	/* Load the free space by block number tree. */
	ra->iter = 0;
	error = xfs_btree_bload(bno_cur, &ra->bno_bload, ra);
	if (error)
		goto out_cur;

	/*
	 * Install the new btrees in the AG header.  After this point the old
	 * btree is no longer accessible and the new tree is live.
	 *
	 * Note: We re-read the AGF here to ensure the buffer type is set
	 * properly.  Since we built a new tree without attaching to the AGF
	 * buffer, the buffer item may have fallen off the buffer.  This ought
	 * to succeed since the AGF is held across transaction rolls.
	 */
	error = xfs_read_agf(sc->mp, sc->tp, sc->sa.agno, 0, &sc->sa.agf_bp);
	if (error)
		goto out_cur;

	/* Commit our new btrees. */
	xfs_allocbt_commit_staged_btree(bno_cur, sc->tp, sc->sa.agf_bp);
	xfs_btree_del_cursor(bno_cur, 0);
	xfs_allocbt_commit_staged_btree(cnt_cur, sc->tp, sc->sa.agf_bp);
	xfs_btree_del_cursor(cnt_cur, 0);

	/* Reset the AGF counters now that we've changed the btree shape. */
	error = xrep_abt_reset_counters(ra, (ra->bno_bload.nr_blocks - 1) +
					    (ra->cnt_bload.nr_blocks - 1));
	if (error)
		goto out_newbt;

	/* Dispose of any unused blocks and the accounting information. */
	xrep_abt_dispose_reservations(ra, error);

	return xrep_roll_ag_trans(sc);

out_cur:
	xfs_btree_del_cursor(cnt_cur, error);
	xfs_btree_del_cursor(bno_cur, error);
out_newbt:
	xrep_abt_dispose_reservations(ra, error);
	return error;
}

/*
 * Now that we've logged the roots of the new btrees, invalidate all of the
 * old blocks and free them.
 */
STATIC int
xrep_abt_remove_old_trees(
	struct xrep_abt		*ra)
{
	/* Free the old inode btree blocks if they're not in use. */
	return xrep_reap_extents(ra->sc, &ra->old_allocbt_blocks,
			&XFS_RMAP_OINFO_AG, XFS_AG_RESV_IGNORE);
}

/* Repair the freespace btrees for some AG. */
int
xrep_allocbt(
	struct xfs_scrub	*sc)
{
	struct xrep_abt		*ra;
	struct xfs_mount	*mp = sc->mp;
	int			error;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	ra = kmem_zalloc(sizeof(struct xrep_abt), KM_NOFS | KM_MAYFAIL);
	if (!ra)
		return -ENOMEM;
	ra->sc = sc;

	/* We rebuild both data structures. */
	sc->sick_mask = XFS_SICK_AG_BNOBT | XFS_SICK_AG_CNTBT;

	xchk_perag_get(sc->mp, &sc->sa);

	/*
	 * Make sure the busy extent list is clear because we can't put
	 * extents on there twice.
	 */
	if (!xfs_extent_busy_list_empty(sc->sa.pag))
		return -EDEADLOCK;

	/* Set up some storage */
	ra->free_records = xfbma_init("freesp extents",
			sizeof(struct xfs_alloc_rec_incore));
	if (IS_ERR(ra->free_records)) {
		error = PTR_ERR(ra->free_records);
		goto out_ra;
	}

	/* Collect the free space data and find the old btree blocks. */
	xbitmap_init(&ra->old_allocbt_blocks);
	error = xrep_abt_find_freespace(ra);
	if (error)
		goto out_bitmap;

	/* Rebuild the free space information. */
	error = xrep_abt_build_new_trees(ra);
	if (error)
		goto out_bitmap;

	/* Kill the old trees. */
	error = xrep_abt_remove_old_trees(ra);

out_bitmap:
	xbitmap_destroy(&ra->old_allocbt_blocks);
	xfbma_destroy(ra->free_records);
out_ra:
	kmem_free(ra);
	return error;
}

/* Make sure both btrees are ok after we've rebuilt them. */
int
xrep_revalidate_allocbt(
	struct xfs_scrub	*sc)
{
	__u32			old_type = sc->sm->sm_type;
	int			error;

	/*
	 * We must update sm_type temporarily so that the tree-to-tree cross
	 * reference checks will work in the correct direction, and also so
	 * that tracing will report correctly if there are more errors.
	 */
	sc->sm->sm_type = XFS_SCRUB_TYPE_BNOBT;
	error = xchk_bnobt(sc);
	if (error)
		goto out;

	sc->sm->sm_type = XFS_SCRUB_TYPE_CNTBT;
	error = xchk_cntbt(sc);
out:
	sc->sm->sm_type = old_type;
	return error;
}
