// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017-2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_btree.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_rtalloc.h"
#include "xfs_inode.h"
#include "xfs_bit.h"
#include "xfs_bmap.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/xfile.h"

/*
 * Realtime Summary
 * ================
 *
 * We check the realtime summary by scanning the realtime bitmap file to create
 * a new summary file incore, and then we compare the computed version against
 * the ondisk version.  We use the 'xfile' functionality to store this
 * (potentially large) amount of data in pageable memory.
 */

/* Set us up to check the rtsummary file. */
int
xchk_setup_rtsummary(
	struct xfs_scrub	*sc)
{
	struct xfs_mount	*mp = sc->mp;
	int			error;

	/*
	 * Create an xfile to construct a new rtsummary file.  The xfile allows
	 * us to avoid pinning kernel memory for this purpose.
	 */
	sc->xfile = xfile_create("rtsummary", mp->m_rsumsize);
	if (IS_ERR(sc->xfile))
		return PTR_ERR(sc->xfile);

	error = xchk_trans_alloc(sc, 0);
	if (error)
		return error;

	/* Allocate a memory buffer for the summary comparison. */
	sc->buf = kmem_alloc_large(sc->mp->m_sb.sb_blocksize, KM_MAYFAIL);
	if (!sc->buf)
		return -ENOMEM;

	error = xchk_install_inode(sc, sc->mp->m_rsumip);
	if (error)
		return error;

	/*
	 * Locking order requires us to take the rtbitmap first.  We must be
	 * careful to unlock it ourselves when we are done with the rtbitmap
	 * file since the scrub infrastructure won't do that for us...
	 */
	xfs_ilock(mp->m_rbmip, XFS_ILOCK_SHARED | XFS_ILOCK_RTBITMAP);

	/* ...and then we can lock the rtsummary inode. */
	sc->ilock_flags = XFS_ILOCK_EXCL | XFS_ILOCK_RTSUM;
	xfs_ilock(sc->ip, sc->ilock_flags);
	return 0;
}

/* Update the summary file to reflect the free extent that we've accumulated. */
STATIC int
xchk_rtsum_record_free(
	struct xfs_trans	*tp,
	struct xfs_rtalloc_rec	*rec,
	void			*priv)
{
	struct xfs_scrub	*sc = priv;
	struct xfs_mount	*mp = sc->mp;
	xfs_rtblock_t		rbmoff;
	unsigned int		offs;
	unsigned int		lenlog;
	xfs_suminfo_t		v = 0;
	int			error = 0;

	if (xchk_should_terminate(sc, &error))
		return error;

	/* Compute the relevant location in the rtsum file. */
	rbmoff = XFS_BITTOBLOCK(mp, rec->ar_startext);
	lenlog = XFS_RTBLOCKLOG(rec->ar_extcount);
	offs = XFS_SUMOFFS(mp, lenlog, rbmoff);

	if (!xfs_verify_rtext(mp, rec->ar_startext, rec->ar_extcount)) {
		xchk_ino_xref_set_corrupt(sc, mp->m_rbmip->i_ino);
		return -EFSCORRUPTED;
	}

	/* Read current rtsummary contents. */
	error = xfile_pread(sc->xfile, &v, sizeof(xfs_suminfo_t),
			sizeof(xfs_suminfo_t) * offs);
	if (error)
		return error;

	/* Bump the summary count... */
	v++;
	trace_xchk_rtsum_record_free(mp, rec->ar_startext, rec->ar_extcount,
			lenlog, offs, v);

	/* ...and write it back. */
	error = xfile_pwrite(sc->xfile, &v, sizeof(xfs_suminfo_t),
			sizeof(xfs_suminfo_t) * offs);
	if (error)
		return error;

	return 0;
}

/* Compute the realtime summary from the realtime bitmap. */
STATIC int
xchk_rtsum_compute(
	struct xfs_scrub	*sc)
{
	struct xfs_mount	*mp = sc->mp;
	unsigned long long	rtbmp_bytes;

	/* If the bitmap size doesn't match the computed size, bail. */
	rtbmp_bytes = howmany_64(mp->m_sb.sb_rextents, NBBY);
	if (roundup_64(rtbmp_bytes, mp->m_sb.sb_blocksize) !=
			mp->m_rbmip->i_disk_size)
		return -EFSCORRUPTED;

	return xfs_rtalloc_query_all(sc->tp, xchk_rtsum_record_free, sc);
}

/* Compare the rtsummary file against the one we computed. */
STATIC int
xchk_rtsum_compare(
	struct xfs_scrub	*sc)
{
	struct xfs_mount	*mp = sc->mp;
	struct xfs_buf		*bp;
	struct xfs_bmbt_irec	map;
	xfs_rtblock_t		off;
	loff_t			pos;
	int			nmap;
	int			error = 0;

	for (off = 0, pos = 0;
	     pos < mp->m_rsumsize;
	     pos += mp->m_sb.sb_blocksize, off++) {
		size_t		count;

		if (xchk_should_terminate(sc, &error) ||
		    (sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT))
			break;

		/* Make sure we have a written extent. */
		nmap = 1;
		error = xfs_bmapi_read(mp->m_rsumip, off, 1, &map, &nmap,
				XFS_DATA_FORK);
		if (!xchk_fblock_process_error(sc, XFS_DATA_FORK, off, &error))
			break;

		if (nmap != 1 || !xfs_bmap_is_written_extent(&map)) {
			xchk_fblock_set_corrupt(sc, XFS_DATA_FORK, off);
			break;
		}

		/* Read a block's worth of ondisk rtsummary file. */
		error = xfs_rtbuf_get(mp, sc->tp, off, 1, &bp);
		if (!xchk_fblock_process_error(sc, XFS_DATA_FORK, off, &error))
			break;

		/* Read a block's worth of computed rtsummary file. */
		count = min_t(loff_t, mp->m_rsumsize - pos,
				mp->m_sb.sb_blocksize);
		error = xfile_pread(sc->xfile, sc->buf, count, pos);
		if (error) {
			xfs_trans_brelse(sc->tp, bp);
			break;
		}

		if (memcmp(bp->b_addr, sc->buf, count) != 0)
			xchk_fblock_set_corrupt(sc, XFS_DATA_FORK, off);

		xfs_trans_brelse(sc->tp, bp);
	}

	return error;
}

/* Scrub the realtime summary. */
int
xchk_rtsummary(
	struct xfs_scrub	*sc)
{
	struct xfs_mount	*mp = sc->mp;
	int			error = 0;

	/* Invoke the fork scrubber. */
	error = xchk_metadata_inode_forks(sc);
	if (error || (sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT))
		goto out_rbm;

	/* Construct the new summary file from the rtbitmap. */
	error = xchk_rtsum_compute(sc);
	if (error == -EFSCORRUPTED) {
		/*
		 * EFSCORRUPTED means the rtbitmap is corrupt, which is an xref
		 * error since we're checking the summary file.
		 */
		xchk_ino_xref_set_corrupt(sc, mp->m_rbmip->i_ino);
		error = 0;
		goto out_rbm;
	}
	if (error)
		goto out_rbm;

	/* Does the computed summary file match the actual rtsummary file? */
	error = xchk_rtsum_compare(sc);

out_rbm:
	/* Unlock the rtbitmap since we're done with it. */
	xfs_iunlock(mp->m_rbmip, XFS_ILOCK_SHARED | XFS_ILOCK_RTBITMAP);
	return error;
}
