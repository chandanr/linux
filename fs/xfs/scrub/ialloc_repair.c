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
#include "xfs_inode.h"
#include "xfs_alloc.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_icache.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_log.h"
#include "xfs_trans_priv.h"
#include "xfs_error.h"
#include "xfs_health.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/bitmap.h"
#include "scrub/array.h"

/*
 * Inode Btree Repair
 * ==================
 *
 * A quick refresher of inode btrees on a v5 filesystem:
 *
 * - Inode records are read into memory in units of 'inode clusters'.  However
 *   many inodes fit in a cluster buffer is the smallest number of inodes that
 *   can be allocated or freed.  Clusters are never smaller than one fs block
 *   though they can span multiple blocks.  The size (in fs blocks) is
 *   computed with xfs_icluster_size_fsb().  The fs block alignment of a
 *   cluster is computed with xfs_ialloc_cluster_alignment().
 *
 * - Each inode btree record can describe a single 'inode chunk'.  The chunk
 *   size is defined to be 64 inodes.  If sparse inodes are enabled, every
 *   inobt record must be aligned to the chunk size; if not, every record must
 *   be aligned to the start of a cluster.  It is possible to construct an XFS
 *   geometry where one inobt record maps to multiple inode clusters; it is
 *   also possible to construct a geometry where multiple inobt records map to
 *   different parts of one inode cluster.
 *
 * - If sparse inodes are not enabled, the smallest unit of allocation for
 *   inode records is enough to contain one inode chunk's worth of inodes.
 *
 * - If sparse inodes are enabled, the holemask field will be active.  Each
 *   bit of the holemask represents 4 potential inodes; if set, the
 *   corresponding space does *not* contain inodes and must be left alone.
 *   Clusters cannot be smaller than 4 inodes.  The smallest unit of allocation
 *   of inode records is one inode cluster.
 *
 * So what's the rebuild algorithm?
 *
 * Iterate the reverse mapping records looking for OWN_INODES and OWN_INOBT
 * records.  The OWN_INOBT records are the old inode btree blocks and will be
 * cleared out after we've rebuilt the tree.  Each possible inode cluster
 * within an OWN_INODES record will be read in; for each possible inobt record
 * associated with that cluster, compute the freemask calculated from the
 * i_mode data in the inode chunk.  For sparse inodes the holemask will be
 * calculated by creating the properly aligned inobt record and punching out
 * any chunk that's missing.  Inode allocations and frees grab the AGI first,
 * so repair protects itself from concurrent access by locking the AGI.
 *
 * Once we've reconstructed all the inode records, we can create new inode
 * btree roots and reload the btrees.  We rebuild both inode trees at the same
 * time because they have the same rmap owner and it would be more complex to
 * figure out if the other tree isn't in need of a rebuild and which OWN_INOBT
 * blocks it owns.  We have all the data we need to build both, so dump
 * everything and start over.
 *
 * We use the prefix 'xrep_ibt' because we rebuild both inode btrees at once.
 */

struct xrep_ibt {
	/* Record under construction. */
	struct xfs_inobt_rec_incore	rie;

	/* new inobt information */
	struct xrep_newbt	new_inobt_info;
	struct xfs_btree_bload	ino_bload;

	/* new finobt information */
	struct xrep_newbt	new_finobt_info;
	struct xfs_btree_bload	fino_bload;

	/* Old inode btree blocks we found in the rmap. */
	struct xbitmap		old_iallocbt_blocks;

	/* Reconstructed inode records. */
	struct xfbma		*inode_records;

	struct xfs_scrub	*sc;

	/* Number of inodes assigned disk space. */
	unsigned int		icount;

	/* Number of inodes in use. */
	unsigned int		iused;

	/* Number of finobt records needed. */
	unsigned int		finobt_recs;

	/* get_record()'s position in the inode record array. */
	uint64_t		iter;
};

/*
 * Is this inode in use?  If the inode is in memory we can tell from i_mode,
 * otherwise we have to check di_mode in the on-disk buffer.  We only care
 * that the high (i.e. non-permission) bits of _mode are zero.  This should be
 * safe because repair keeps all AG headers locked until the end, and process
 * trying to perform an inode allocation/free must lock the AGI.
 *
 * @cluster_ag_base is the inode offset of the cluster within the AG.
 * @cluster_bp is the cluster buffer.
 * @cluster_index is the inode offset within the inode cluster.
 */
STATIC int
xrep_ibt_check_ifree(
	struct xrep_ibt		*ri,
	xfs_agino_t		cluster_ag_base,
	struct xfs_buf		*cluster_bp,
	unsigned int		cluster_index,
	bool			*inuse)
{
	struct xfs_scrub	*sc = ri->sc;
	struct xfs_mount	*mp = sc->mp;
	struct xfs_dinode	*dip;
	xfs_ino_t		fsino;
	xfs_agnumber_t		agno = ri->sc->sa.agno;
	unsigned int		cluster_buf_base;
	unsigned int		offset;
	int			error;

	fsino = XFS_AGINO_TO_INO(mp, agno, cluster_ag_base + cluster_index);

	/* Inode uncached or half assembled, read disk buffer */
	cluster_buf_base = XFS_INO_TO_OFFSET(mp, cluster_ag_base);
	offset = (cluster_buf_base + cluster_index) * mp->m_sb.sb_inodesize;
	if (offset >= BBTOB(cluster_bp->b_length))
		return -EFSCORRUPTED;
	dip = xfs_buf_offset(cluster_bp, offset);
	if (be16_to_cpu(dip->di_magic) != XFS_DINODE_MAGIC)
		return -EFSCORRUPTED;

	if (dip->di_version >= 3 && be64_to_cpu(dip->di_ino) != fsino)
		return -EFSCORRUPTED;

	/* Will the in-core inode tell us if it's in use? */
	error = xfs_icache_inode_is_allocated(mp, sc->tp, fsino, inuse);
	if (!error)
		return 0;

	*inuse = dip->di_mode != 0;
	return 0;
}

/* Stash the accumulated inobt record for rebuilding. */
STATIC int
xrep_ibt_stash(
	struct xrep_ibt		*ri)
{
	int			error = 0;

	if (xchk_should_terminate(ri->sc, &error))
		return error;

	ri->rie.ir_freecount = xfs_inobt_rec_freecount(&ri->rie);
	if (ri->rie.ir_freecount > 0)
		ri->finobt_recs++;

	trace_xrep_ibt_found(ri->sc->mp, ri->sc->sa.agno, &ri->rie);

	error = xfbma_append(ri->inode_records, &ri->rie);
	if (error)
		return error;

	ri->rie.ir_startino = NULLAGINO;
	return 0;
}

/*
 * Given an extent of inodes and an inode cluster buffer, calculate the
 * location of the corresponding inobt record (creating it if necessary),
 * then update the parts of the holemask and freemask of that record that
 * correspond to the inode extent we were given.
 *
 * @cluster_ir_startino is the AG inode number of an inobt record that we're
 * proposing to create for this inode cluster.  If sparse inodes are enabled,
 * we must round down to a chunk boundary to find the actual sparse record.
 * @cluster_bp is the buffer of the inode cluster.
 * @nr_inodes is the number of inodes to check from the cluster.
 */
STATIC int
xrep_ibt_cluster_record(
	struct xrep_ibt		*ri,
	xfs_agino_t		cluster_ir_startino,
	struct xfs_buf		*cluster_bp,
	unsigned int		nr_inodes)
{
	struct xfs_scrub	*sc = ri->sc;
	struct xfs_mount	*mp = sc->mp;
	xfs_agino_t		ir_startino;
	unsigned int		cluster_base;
	unsigned int		cluster_index;
	bool			inuse;
	int			error = 0;

	ir_startino = cluster_ir_startino;
	if (xfs_sb_version_hassparseinodes(&mp->m_sb))
		ir_startino = rounddown(ir_startino, XFS_INODES_PER_CHUNK);
	cluster_base = cluster_ir_startino - ir_startino;

	/*
	 * If the accumulated inobt record doesn't map this cluster, add it to
	 * the list and reset it.
	 */
	if (ri->rie.ir_startino != NULLAGINO &&
	    ri->rie.ir_startino + XFS_INODES_PER_CHUNK <= ir_startino) {
		error = xrep_ibt_stash(ri);
		if (error)
			return error;
	}

	if (ri->rie.ir_startino == NULLAGINO) {
		ri->rie.ir_startino = ir_startino;
		ri->rie.ir_free = XFS_INOBT_ALL_FREE;
		ri->rie.ir_holemask = 0xFFFF;
		ri->rie.ir_count = 0;
	}

	/* Record the whole cluster. */
	ri->icount += nr_inodes;
	ri->rie.ir_count += nr_inodes;
	ri->rie.ir_holemask &= ~xfs_inobt_maskn(
				cluster_base / XFS_INODES_PER_HOLEMASK_BIT,
				nr_inodes / XFS_INODES_PER_HOLEMASK_BIT);

	/* Which inodes within this cluster are free? */
	for (cluster_index = 0; cluster_index < nr_inodes; cluster_index++) {
		error = xrep_ibt_check_ifree(ri, cluster_ir_startino,
				cluster_bp, cluster_index, &inuse);
		if (error)
			return error;
		if (!inuse)
			continue;
		ri->iused++;
		ri->rie.ir_free &= ~XFS_INOBT_MASK(cluster_base +
						   cluster_index);
	}
	return 0;
}

/*
 * For each inode cluster covering the physical extent recorded by the rmapbt,
 * we must calculate the properly aligned startino of that cluster, then
 * iterate each cluster to fill in used and filled masks appropriately.  We
 * then use the (startino, used, filled) information to construct the
 * appropriate inode records.
 */
STATIC int
xrep_ibt_process_cluster(
	struct xrep_ibt		*ri,
	xfs_agblock_t		cluster_bno)
{
	struct xfs_imap		imap;
	struct xfs_buf		*cluster_bp;
	struct xfs_scrub	*sc = ri->sc;
	struct xfs_mount	*mp = sc->mp;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	xfs_agino_t		cluster_ag_base;
	xfs_agino_t		irec_index;
	unsigned int		nr_inodes;
	int			error;

	nr_inodes = min_t(unsigned int, igeo->inodes_per_cluster,
			XFS_INODES_PER_CHUNK);

	/*
	 * Grab the inode cluster buffer.  This is safe to do with a broken
	 * inobt because imap_to_bp directly maps the buffer without touching
	 * either inode btree.
	 */
	imap.im_blkno = XFS_AGB_TO_DADDR(mp, sc->sa.agno, cluster_bno);
	imap.im_len = XFS_FSB_TO_BB(mp, igeo->blocks_per_cluster);
	imap.im_boffset = 0;
	error = xfs_imap_to_bp(mp, sc->tp, &imap, &cluster_bp);
	if (error)
		return error;

	/*
	 * Record the contents of each possible inobt record mapping this
	 * cluster.
	 */
	cluster_ag_base = XFS_AGB_TO_AGINO(mp, cluster_bno);
	for (irec_index = 0;
	     irec_index < igeo->inodes_per_cluster;
	     irec_index += XFS_INODES_PER_CHUNK) {
		error = xrep_ibt_cluster_record(ri,
				cluster_ag_base + irec_index, cluster_bp,
				nr_inodes);
		if (error)
			break;

	}

	xfs_trans_brelse(sc->tp, cluster_bp);
	return error;
}

/* Check for any obvious conflicts in the inode chunk extent. */
STATIC int
xrep_ibt_check_inode_ext(
	struct xfs_scrub	*sc,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len)
{
	struct xfs_mount	*mp = sc->mp;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	xfs_agino_t		agino;
	bool			is_freesp;
	int			error;

	/* Inode records must be within the AG. */
	if (!xfs_verify_agbext(mp, sc->sa.agno, agbno, len))
		return -EFSCORRUPTED;

	/* The entire record must align to the inode cluster size. */
	if (!IS_ALIGNED(agbno, igeo->blocks_per_cluster) ||
	    !IS_ALIGNED(agbno + len, igeo->blocks_per_cluster))
		return -EFSCORRUPTED;

	/*
	 * The entire record must also adhere to the inode cluster alignment
	 * size if sparse inodes are not enabled.
	 */
	if (!xfs_sb_version_hassparseinodes(&mp->m_sb) &&
	    (!IS_ALIGNED(agbno, igeo->cluster_align) ||
	     !IS_ALIGNED(agbno + len, igeo->cluster_align)))
		return -EFSCORRUPTED;

	/*
	 * On a sparse inode fs, this cluster could be part of a sparse chunk.
	 * Sparse clusters must be aligned to sparse chunk alignment.
	 */
	if (xfs_sb_version_hassparseinodes(&mp->m_sb) &&
	    (!IS_ALIGNED(agbno, mp->m_sb.sb_spino_align) ||
	     !IS_ALIGNED(agbno + len, mp->m_sb.sb_spino_align)))
		return -EFSCORRUPTED;

	/* Make sure the entire range of blocks are valid AG inodes. */
	agino = XFS_AGB_TO_AGINO(mp, agbno);
	if (!xfs_verify_agino(sc->mp, sc->sa.agno, agino))
		return -EFSCORRUPTED;

	agino = XFS_AGB_TO_AGINO(mp, agbno + len) - 1;
	if (!xfs_verify_agino(sc->mp, sc->sa.agno, agino))
		return -EFSCORRUPTED;

	/* Make sure this isn't free space. */
	error = xfs_alloc_has_record(sc->sa.bno_cur, agbno, len, &is_freesp);
	if (error)
		return error;
	if (is_freesp)
		return -EFSCORRUPTED;

	return 0;
}

/* Found a fragment of the old inode btrees; dispose of them later. */
STATIC int
xrep_ibt_record_old_btree_blocks(
	struct xrep_ibt		*ri,
	struct xfs_rmap_irec	*rec)
{
	struct xfs_mount	*mp = ri->sc->mp;
	xfs_fsblock_t		fsbno;

	if (!xfs_verify_agbext(mp, ri->sc->sa.agno, rec->rm_startblock,
				rec->rm_blockcount))
		return -EFSCORRUPTED;

	fsbno = XFS_AGB_TO_FSB(mp, ri->sc->sa.agno, rec->rm_startblock);
	return xbitmap_set(&ri->old_iallocbt_blocks, fsbno,
			rec->rm_blockcount);
}

/* Record extents that belong to inode btrees. */
STATIC int
xrep_ibt_walk_rmap(
	struct xfs_btree_cur	*cur,
	struct xfs_rmap_irec	*rec,
	void			*priv)
{
	struct xrep_ibt		*ri = priv;
	struct xfs_mount	*mp = cur->bc_mp;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	xfs_agblock_t		cluster_base;
	int			error = 0;

	if (xchk_should_terminate(ri->sc, &error))
		return error;

	if (rec->rm_owner == XFS_RMAP_OWN_INOBT)
		return xrep_ibt_record_old_btree_blocks(ri, rec);

	/* Skip extents which are not owned by this inode and fork. */
	if (rec->rm_owner != XFS_RMAP_OWN_INODES)
		return 0;

	error = xrep_ibt_check_inode_ext(ri->sc, rec->rm_startblock,
			rec->rm_blockcount);
	if (error)
		return error;

	trace_xrep_ibt_walk_rmap(mp, ri->sc->sa.agno, rec->rm_startblock,
			rec->rm_blockcount, rec->rm_owner, rec->rm_offset,
			rec->rm_flags);

	/*
	 * Record the free/hole masks for each inode cluster that could be
	 * mapped by this rmap record.
	 */
	for (cluster_base = 0;
	     cluster_base < rec->rm_blockcount;
	     cluster_base += igeo->blocks_per_cluster) {
		error = xrep_ibt_process_cluster(ri,
				rec->rm_startblock + cluster_base);
		if (error)
			return error;
	}

	return 0;
}

/* Compare two ialloc extents. */
static int
xfs_inobt_rec_incore_cmp(
	const void				*a,
	const void				*b)
{
	const struct xfs_inobt_rec_incore	*ap = a;
	const struct xfs_inobt_rec_incore	*bp = b;

	if (ap->ir_startino > bp->ir_startino)
		return 1;
	else if (ap->ir_startino < bp->ir_startino)
		return -1;
	return 0;
}

/*
 * Iterate all reverse mappings to find the inodes (OWN_INODES) and the inode
 * btrees (OWN_INOBT).  Figure out if we have enough free space to reconstruct
 * the inode btrees.  The caller must clean up the lists if anything goes
 * wrong.
 */
STATIC int
xrep_ibt_find_inodes(
	struct xrep_ibt		*ri)
{
	struct xfs_scrub	*sc = ri->sc;
	int			error;

	ri->rie.ir_startino = NULLAGINO;

	/* Collect all reverse mappings for inode blocks. */
	xrep_ag_btcur_init(sc, &sc->sa);
	error = xfs_rmap_query_all(sc->sa.rmap_cur, xrep_ibt_walk_rmap, ri);
	xchk_ag_btcur_free(&sc->sa);
	if (error)
		return error;

	/* If we have a record ready to go, add it to the array. */
	if (ri->rie.ir_startino == NULLAGINO)
		return 0;

	return xrep_ibt_stash(ri);
}

/* Update the AGI counters. */
STATIC int
xrep_ibt_reset_counters(
	struct xrep_ibt		*ri)
{
	struct xfs_scrub	*sc = ri->sc;
	struct xfs_agi		*agi = sc->sa.agi_bp->b_addr;
	struct xfs_perag	*pag = sc->sa.pag;
	struct xfs_buf		*bp;
	unsigned int		freecount = ri->icount - ri->iused;

	/* Trigger inode count recalculation */
	xfs_force_summary_recalc(sc->mp);

	/*
	 * Mark the pagi information stale and use the accessor function to
	 * forcibly reload it from the values we just logged.  We still own
	 * the AGI bp so we can throw away bp.
	 */
	ASSERT(pag->pagi_init);
	pag->pagi_init = 0;

	agi->agi_count = cpu_to_be32(ri->icount);
	agi->agi_freecount = cpu_to_be32(freecount);
	xfs_ialloc_log_agi(sc->tp, sc->sa.agi_bp,
			   XFS_AGI_COUNT | XFS_AGI_FREECOUNT);

	return xfs_ialloc_read_agi(sc->mp, sc->tp, sc->sa.agno, &bp);
}

/* Retrieve finobt data for bulk load. */
STATIC int
xrep_fibt_get_record(
	struct xfs_btree_cur		*cur,
	void				*priv)
{
	struct xfs_inobt_rec_incore	*irec = &cur->bc_rec.i;
	struct xrep_ibt			*ri = priv;
	int				error;

	do {
		error = xfbma_get(ri->inode_records, ri->iter++, irec);
	} while (error == 0 && xfs_inobt_rec_freecount(irec) == 0);

	return error;
}

/* Retrieve inobt data for bulk load. */
STATIC int
xrep_ibt_get_record(
	struct xfs_btree_cur		*cur,
	void				*priv)
{
	struct xfs_inobt_rec_incore	*irec = &cur->bc_rec.i;
	struct xrep_ibt			*ri = priv;

	return xfbma_get(ri->inode_records, ri->iter++, irec);
}

/* Feed one of the new inobt blocks to the bulk loader. */
STATIC int
xrep_ibt_claim_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	void			*priv)
{
	struct xrep_ibt		*ri = priv;
	int			error;

	error = xrep_newbt_relog_efis(&ri->new_inobt_info);
	if (error)
		return error;

	return xrep_newbt_claim_block(cur, &ri->new_inobt_info, ptr);
}

/* Feed one of the new finobt blocks to the bulk loader. */
STATIC int
xrep_fibt_claim_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	void			*priv)
{
	struct xrep_ibt		*ri = priv;
	int			error;

	error = xrep_newbt_relog_efis(&ri->new_finobt_info);
	if (error)
		return error;

	return xrep_newbt_claim_block(cur, &ri->new_finobt_info, ptr);
}

/* Build new inode btrees and dispose of the old one. */
STATIC int
xrep_ibt_build_new_trees(
	struct xrep_ibt		*ri)
{
	struct xfs_scrub	*sc = ri->sc;
	struct xfs_btree_cur	*ino_cur;
	struct xfs_btree_cur	*fino_cur = NULL;
	bool			need_finobt;
	int			error;

	need_finobt = xfs_sb_version_hasfinobt(&sc->mp->m_sb);

	ri->ino_bload.claim_block = xrep_ibt_claim_block;
	ri->ino_bload.get_record = xrep_ibt_get_record;
	xrep_bload_estimate_slack(ri->sc, &ri->ino_bload);

	if (need_finobt) {
		ri->fino_bload.claim_block = xrep_fibt_claim_block;
		ri->fino_bload.get_record = xrep_fibt_get_record;
		xrep_bload_estimate_slack(ri->sc, &ri->fino_bload);
	}

	/*
	 * Sort the inode extents by startino or else the btree records will
	 * be in the wrong order.
	 */
	error = xfbma_sort(ri->inode_records, xfs_inobt_rec_incore_cmp);
	if (error)
		return error;

	/*
	 * Create new btrees for staging all the inobt records we collected
	 * earlier.  These btrees will not be rooted in the AGI until we've
	 * successfully reloaded the tree.
	 */

	/* Set up inobt staging cursor. */
	xrep_newbt_init_ag(&ri->new_inobt_info, sc, &XFS_RMAP_OINFO_INOBT,
			XFS_AGB_TO_FSB(sc->mp, sc->sa.agno,
				       XFS_IBT_BLOCK(sc->mp)),
			XFS_AG_RESV_NONE);
	ino_cur = xfs_inobt_stage_cursor(sc->mp, &ri->new_inobt_info.afake,
			sc->sa.agno, XFS_BTNUM_INO);
	error = xfs_btree_bload_compute_geometry(ino_cur, &ri->ino_bload,
			xfbma_length(ri->inode_records));
	if (error)
		goto err_inocur;

	/* Set up finobt staging cursor. */
	if (need_finobt) {
		enum xfs_ag_resv_type	resv = XFS_AG_RESV_METADATA;

		if (sc->mp->m_finobt_nores)
			resv = XFS_AG_RESV_NONE;

		xrep_newbt_init_ag(&ri->new_finobt_info, sc,
				&XFS_RMAP_OINFO_INOBT,
				XFS_AGB_TO_FSB(sc->mp, sc->sa.agno,
					       XFS_FIBT_BLOCK(sc->mp)),
				resv);
		fino_cur = xfs_inobt_stage_cursor(sc->mp,
				&ri->new_finobt_info.afake, sc->sa.agno,
				XFS_BTNUM_FINO);
		error = xfs_btree_bload_compute_geometry(fino_cur,
				&ri->fino_bload, ri->finobt_recs);
		if (error)
			goto err_finocur;
	}

	/* Reserve all the space we need to build the new btrees. */
	error = xrep_newbt_alloc_blocks(&ri->new_inobt_info,
			ri->ino_bload.nr_blocks);
	if (error)
		goto err_finocur;

	if (need_finobt) {
		error = xrep_newbt_alloc_blocks(&ri->new_finobt_info,
				ri->fino_bload.nr_blocks);
		if (error)
			goto err_finocur;
	}

	/* Add all inobt records. */
	ri->iter = 0;
	error = xfs_btree_bload(ino_cur, &ri->ino_bload, ri);
	if (error)
		goto err_finocur;

	/* Add all finobt records. */
	if (need_finobt) {
		ri->iter = 0;
		error = xfs_btree_bload(fino_cur, &ri->fino_bload, ri);
		if (error)
			goto err_finocur;
	}

	/*
	 * Re-read the AGI so that the buffer type is set properly.  Since we
	 * built a new tree without dirtying the AGI, the buffer item may have
	 * fallen off the buffer.  This ought to succeed since the AGI is held
	 * across transaction rolls.
	 */
	error = xfs_read_agi(sc->mp, sc->tp, sc->sa.agno, &sc->sa.agi_bp);
	if (error)
		goto err_finocur;

	/* Install new btree roots. */
	xfs_inobt_commit_staged_btree(ino_cur, sc->tp, sc->sa.agi_bp);
	xfs_btree_del_cursor(ino_cur, 0);

	if (fino_cur) {
		xfs_inobt_commit_staged_btree(fino_cur, sc->tp, sc->sa.agi_bp);
		xfs_btree_del_cursor(fino_cur, 0);
	}

	/* Reset the AGI counters now that we've changed the inode roots. */
	error = xrep_ibt_reset_counters(ri);
	if (error)
		goto err_finobt;

	/* Free unused blocks and bitmap. */
	if (need_finobt)
		xrep_newbt_destroy(&ri->new_finobt_info, error);
	xrep_newbt_destroy(&ri->new_inobt_info, error);

	return xrep_roll_ag_trans(sc);

err_finocur:
	if (need_finobt)
		xfs_btree_del_cursor(fino_cur, error);
err_inocur:
	xfs_btree_del_cursor(ino_cur, error);
err_finobt:
	if (need_finobt)
		xrep_newbt_destroy(&ri->new_finobt_info, error);
	xrep_newbt_destroy(&ri->new_inobt_info, error);
	return error;
}

/*
 * Now that we've logged the roots of the new btrees, invalidate all of the
 * old blocks and free them.
 */
STATIC int
xrep_ibt_remove_old_trees(
	struct xrep_ibt		*ri)
{
	struct xfs_scrub	*sc = ri->sc;
	int			error;

	/* Free the old inode btree blocks if they're not in use. */
	error = xrep_reap_extents(sc, &ri->old_iallocbt_blocks,
			&XFS_RMAP_OINFO_INOBT, XFS_AG_RESV_NONE);
	if (error)
		return error;

	/*
	 * If the finobt is enabled and has a per-AG reservation, make sure we
	 * reinitialize the per-AG reservations.
	 */
	if (xfs_sb_version_hasfinobt(&sc->mp->m_sb) && !sc->mp->m_finobt_nores)
		sc->flags |= XREP_RESET_PERAG_RESV;

	return 0;
}

/* Repair both inode btrees. */
int
xrep_iallocbt(
	struct xfs_scrub	*sc)
{
	struct xrep_ibt		*ri;
	struct xfs_mount	*mp = sc->mp;
	int			error = 0;

	/* We require the rmapbt to rebuild anything. */
	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return -EOPNOTSUPP;

	ri = kmem_zalloc(sizeof(struct xrep_ibt), KM_NOFS | KM_MAYFAIL);
	if (!ri)
		return -ENOMEM;
	ri->sc = sc;

	xchk_perag_get(sc->mp, &sc->sa);

	/* We rebuild both inode btrees. */
	sc->sick_mask = XFS_SICK_AG_INOBT | XFS_SICK_AG_FINOBT;

	/* Set up some storage */
	ri->inode_records = xfbma_init("inode records",
			sizeof(struct xfs_inobt_rec_incore));
	if (IS_ERR(ri->inode_records)) {
		error = PTR_ERR(ri->inode_records);
		goto out_ri;
	}

	/* Collect the inode data and find the old btree blocks. */
	xbitmap_init(&ri->old_iallocbt_blocks);
	error = xrep_ibt_find_inodes(ri);
	if (error)
		goto out_bitmap;

	/* Rebuild the inode indexes. */
	error = xrep_ibt_build_new_trees(ri);
	if (error)
		goto out_bitmap;

	/* Kill the old tree. */
	error = xrep_ibt_remove_old_trees(ri);

out_bitmap:
	xbitmap_destroy(&ri->old_iallocbt_blocks);
	xfbma_destroy(ri->inode_records);
out_ri:
	kmem_free(ri);
	return error;
}

/* Make sure both btrees are ok after we've rebuilt them. */
int
xrep_revalidate_iallocbt(
	struct xfs_scrub	*sc)
{
	__u32			old_type = sc->sm->sm_type;
	int			error;

	/*
	 * We must update sm_type temporarily so that the tree-to-tree cross
	 * reference checks will work in the correct direction, and also so
	 * that tracing will report correctly if there are more errors.
	 */
	sc->sm->sm_type = XFS_SCRUB_TYPE_INOBT;
	error = xchk_inobt(sc);
	if (error)
		goto out;

	if (xfs_sb_version_hasfinobt(&sc->mp->m_sb)) {
		sc->sm->sm_type = XFS_SCRUB_TYPE_FINOBT;
		error = xchk_finobt(sc);
	}

out:
	sc->sm->sm_type = old_type;
	return error;
}
