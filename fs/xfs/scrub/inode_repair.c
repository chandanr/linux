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
#include "xfs_icache.h"
#include "xfs_inode_buf.h"
#include "xfs_inode_fork.h"
#include "xfs_ialloc.h"
#include "xfs_da_format.h"
#include "xfs_reflink.h"
#include "xfs_alloc.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_bmap.h"
#include "xfs_bmap_btree.h"
#include "xfs_bmap_util.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_quota_defs.h"
#include "xfs_attr_leaf.h"
#include "xfs_log_priv.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/btree.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/*
 * Inode Repair
 *
 * Roughly speaking, inode problems can be classified based on whether or not
 * they trip the dinode verifiers.  If those trip, then we won't be able to
 * _iget ourselves the inode.
 *
 * Therefore, the xrep_dinode_* functions fix anything that will cause the
 * inode buffer verifier or the dinode verifier.  The xrep_inode_* functions
 * fix things on live incore inodes.
 */

/* Blocks and extents associated with an inode, according to rmap records. */
struct xrep_dinode_stats {
	struct xfs_scrub	*sc;

	/* Blocks in use on the data device by data extents or bmbt blocks. */
	xfs_rfsblock_t		data_blocks;

	/* Blocks in use on the rt device. */
	xfs_rfsblock_t		rt_blocks;

	/* Blocks in use by the attr fork. */
	xfs_rfsblock_t		attr_blocks;

	/* Physical block containing data block 0. */
	xfs_fsblock_t		block0;

	/* Number of data device extents for the data fork. */
	xfs_extnum_t		data_extents;

	/*
	 * Number of realtime device extents for the data fork.  If
	 * data_extents and rt_extents indicate that the data fork has extents
	 * on both devices, we'll just back away slowly.
	 */
	xfs_extnum_t		rt_extents;

	/* Number of (data device) extents for the attr fork. */
	xfs_aextnum_t		attr_extents;
};

/* Make sure this buffer can pass the inode buffer verifier. */
STATIC void
xrep_dinode_buf(
	struct xfs_scrub	*sc,
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = sc->mp;
	struct xfs_trans	*tp = sc->tp;
	struct xfs_dinode	*dip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	int			ioff;
	int			i;
	int			ni;
	bool			crc_ok;
	bool			magic_ok;
	bool			unlinked_ok;

	ni = XFS_BB_TO_FSB(mp, bp->b_length) * mp->m_sb.sb_inopblock;
	agno = xfs_daddr_to_agno(mp, XFS_BUF_ADDR(bp));
	for (i = 0; i < ni; i++) {
		ioff = i << mp->m_sb.sb_inodelog;
		dip = xfs_buf_offset(bp, ioff);
		agino = be32_to_cpu(dip->di_next_unlinked);

		unlinked_ok = magic_ok = crc_ok = false;

		if (xfs_verify_agino_or_null(sc->mp, agno, agino))
			unlinked_ok = true;

		if (dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
		    xfs_dinode_good_version(&mp->m_sb, dip->di_version))
			magic_ok = true;

		if (xfs_verify_cksum((char *)dip, mp->m_sb.sb_inodesize,
				XFS_DINODE_CRC_OFF))
			crc_ok = true;

		if (magic_ok && unlinked_ok && crc_ok)
			continue;

		if (!magic_ok) {
			dip->di_magic = cpu_to_be16(XFS_DINODE_MAGIC);
			dip->di_version = 3;
		}
		if (!unlinked_ok)
			dip->di_next_unlinked = cpu_to_be32(NULLAGINO);
		xfs_dinode_calc_crc(mp, dip);
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DINO_BUF);
		xfs_trans_log_buf(tp, bp, ioff, ioff + sizeof(*dip) - 1);
	}
}

/* Reinitialize things that never change in an inode. */
STATIC void
xrep_dinode_header(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip)
{
	trace_xrep_dinode_header(sc, dip);

	dip->di_magic = cpu_to_be16(XFS_DINODE_MAGIC);
	if (!xfs_dinode_good_version(&sc->mp->m_sb, dip->di_version))
		dip->di_version = 3;
	dip->di_ino = cpu_to_be64(sc->sm->sm_ino);
	uuid_copy(&dip->di_uuid, &sc->mp->m_sb.sb_meta_uuid);
	dip->di_gen = cpu_to_be32(sc->sm->sm_gen);
}

/* Parse enough of the directory block header to guess if this is a dir. */
static inline bool
xrep_dinode_is_dir(
	xfs_ino_t			ino,
	xfs_daddr_t			daddr,
	struct xfs_buf			*bp)
{
	struct xfs_dir3_blk_hdr		*hdr3 = bp->b_addr;
	struct xfs_dir2_data_free	*bf;
	struct xfs_mount		*mp = bp->b_mount;
	xfs_lsn_t			lsn = be64_to_cpu(hdr3->lsn);

	/* Does the dir3 header match the filesystem? */
	if (hdr3->magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) &&
	    hdr3->magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC))
		return false;

	if (be64_to_cpu(hdr3->owner) != ino)
		return false;

	if (!uuid_equal(&hdr3->uuid, &mp->m_sb.sb_meta_uuid))
		return false;

	if (be64_to_cpu(hdr3->blkno) != daddr)
		return false;

	/* Directory blocks are always logged and must have a valid LSN. */
	if (lsn == NULLCOMMITLSN)
		return false;
	if (!xlog_valid_lsn(mp->m_log, lsn))
		return false;

	/*
	 * bestfree information lives immediately after the end of the header,
	 * so we won't run off the end of the buffer.
	 */
	bf = xfs_dir2_data_bestfree_p(mp, bp->b_addr);
	if (!bf[0].length && bf[0].offset)
		return false;
	if (!bf[1].length && bf[1].offset)
		return false;
	if (!bf[2].length && bf[2].offset)
		return false;

	if (be16_to_cpu(bf[0].length) < be16_to_cpu(bf[1].length))
		return false;
	if (be16_to_cpu(bf[1].length) < be16_to_cpu(bf[2].length))
		return false;

	return true;
}

/* Guess the mode of this file from the contents. */
STATIC uint16_t
xrep_dinode_guess_mode(
	struct xfs_dinode	*dip,
	struct xrep_dinode_stats	*dis)
{
	struct xfs_buf		*bp;
	xfs_daddr_t		daddr;
	uint64_t		fsize = be64_to_cpu(dip->di_size);
	unsigned int		dfork_sz = XFS_DFORK_DSIZE(dip, dis->sc->mp);
	uint16_t		mode = S_IFREG;
	int			error;

	switch (dip->di_format) {
	case XFS_DINODE_FMT_LOCAL:
		/*
		 * If the data fork is local format, the size of the data area
		 * is reasonable and is big enough to contain the entire file,
		 * we can guess the file type from the local data.
		 *
		 * If there are no nulls, guess this is a symbolic link.
		 * Otherwise, this is probably a shortform directory.
		 */
		if (dfork_sz <= XFS_LITINO(dis->sc->mp) && dfork_sz >= fsize) {
			if (!memchr(XFS_DFORK_DPTR(dip), 0, fsize))
				return S_IFLNK;
			return S_IFDIR;
		}

		/* By default, we guess regular file. */
		return S_IFREG;
	case XFS_DINODE_FMT_DEV:
		/*
		 * If the data fork is dev format, the size of the data area is
		 * reasonable and large enough to store a dev_t, and the file
		 * size is zero, this could be a blockdev, a chardev, a fifo,
		 * or a socket.  There is no solid way to distinguish between
		 * those choices, so we guess blockdev if the device number is
		 * nonzero and chardev if it's zero (aka whiteout).
		 */
		if (dfork_sz <= XFS_LITINO(dis->sc->mp) &&
		    dfork_sz >= sizeof(__be32) && fsize == 0) {
			xfs_dev_t	dev = xfs_dinode_get_rdev(dip);

			return dev != 0 ? S_IFBLK : S_IFCHR;
		}

		/* By default, we guess regular file. */
		return S_IFREG;
	case XFS_DINODE_FMT_EXTENTS:
	case XFS_DINODE_FMT_BTREE:
		/* There are data blocks to examine below. */
		break;
	default:
		/* Everything else is considered a regular file. */
		return S_IFREG;
	}

	/* There are no zero-length directories. */
	if (fsize == 0)
		return S_IFREG;

	/*
	 * If we didn't find a written mapping for file block zero, we'll guess
	 * that it's a sparse regular file.
	 */
	if (dis->block0 == NULLFSBLOCK)
		return S_IFREG;

	/* Directories can't have rt extents. */
	if (dis->rt_extents > 0)
		return S_IFREG;

	/*
	 * Read the first block of the file.  Since we have no idea what kind
	 * of file geometry (e.g. dirblock size) we might be reading into, use
	 * an uncached buffer so that we don't pollute the buffer cache.  We
	 * can't do uncached mapped buffers, so the best we can do is guess
	 * from the directory header.
	 */
	daddr = XFS_FSB_TO_DADDR(dis->sc->mp, dis->block0);
	error = xfs_buf_read_uncached(dis->sc->mp->m_ddev_targp, daddr,
			XFS_FSS_TO_BB(dis->sc->mp, 1), 0, &bp, NULL);
	if (error)
		return S_IFREG;

	if (xrep_dinode_is_dir(dis->sc->sm->sm_ino, daddr, bp))
		mode = S_IFDIR;

	xfs_buf_relse(bp);
	return mode;
}

/* Turn di_mode into /something/ recognizable. */
STATIC void
xrep_dinode_mode(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip,
	struct xrep_dinode_stats *dis)
{
	uint16_t		mode;

	trace_xrep_dinode_mode(sc, dip);

	mode = be16_to_cpu(dip->di_mode);
	if (mode == 0 || xfs_mode_to_ftype(mode) != XFS_DIR3_FT_UNKNOWN)
		return;

	/* bad mode, so we set it to a file that only root can read */
	mode = xrep_dinode_guess_mode(dip, dis);
	dip->di_mode = cpu_to_be16(mode);
	dip->di_uid = 0;
	dip->di_gid = 0;
}

/* Fix any conflicting flags that the verifiers complain about. */
STATIC void
xrep_dinode_flags(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip,
	bool			isrt)
{
	struct xfs_mount	*mp = sc->mp;
	uint64_t		flags2;
	uint16_t		mode;
	uint16_t		flags;

	trace_xrep_dinode_flags(sc, dip);

	mode = be16_to_cpu(dip->di_mode);
	flags = be16_to_cpu(dip->di_flags);
	flags2 = be64_to_cpu(dip->di_flags2);

	if (isrt)
		flags |= XFS_DIFLAG_REALTIME;
	else
		flags &= ~XFS_DIFLAG_REALTIME;

	if (xfs_sb_version_hasreflink(&mp->m_sb) && S_ISREG(mode))
		flags2 |= XFS_DIFLAG2_REFLINK;
	else
		flags2 &= ~(XFS_DIFLAG2_REFLINK | XFS_DIFLAG2_COWEXTSIZE);
	if (flags & XFS_DIFLAG_REALTIME)
		flags2 &= ~XFS_DIFLAG2_REFLINK;
	if (flags2 & XFS_DIFLAG2_REFLINK)
		flags2 &= ~XFS_DIFLAG2_DAX;
	if (!xfs_sb_version_hasbigtime(&mp->m_sb))
		flags2 &= ~XFS_DIFLAG2_BIGTIME;
	dip->di_flags = cpu_to_be16(flags);
	dip->di_flags2 = cpu_to_be64(flags2);
}

/*
 * Blow out symlink; now it points to the current dir.  We don't have to worry
 * about incore state because this inode is failing the verifiers.
 */
STATIC void
xrep_dinode_zap_symlink(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip)
{
	char			*p;

	trace_xrep_dinode_zap_symlink(sc, dip);

	dip->di_format = XFS_DINODE_FMT_LOCAL;
	dip->di_size = cpu_to_be64(1);
	p = XFS_DFORK_PTR(dip, XFS_DATA_FORK);
	*p = '.';
}

/*
 * Blow out dir, make it point to the root.  In the future repair will
 * reconstruct this directory for us.  Note that there's no in-core directory
 * inode because the sf verifier tripped, so we don't have to worry about the
 * dentry cache.
 */
STATIC void
xrep_dinode_zap_dir(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip)
{
	struct xfs_mount	*mp = sc->mp;
	struct xfs_dir2_sf_hdr	*sfp;
	int			i8count;

	trace_xrep_dinode_zap_dir(sc, dip);

	dip->di_format = XFS_DINODE_FMT_LOCAL;
	i8count = mp->m_sb.sb_rootino > XFS_DIR2_MAX_SHORT_INUM;
	sfp = XFS_DFORK_PTR(dip, XFS_DATA_FORK);
	sfp->count = 0;
	sfp->i8count = i8count;
	xfs_dir2_sf_put_parent_ino(sfp, mp->m_sb.sb_rootino);
	dip->di_size = cpu_to_be64(xfs_dir2_sf_hdr_size(i8count));
}

/* Make sure we don't have a garbage file size. */
STATIC void
xrep_dinode_size(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip)
{
	uint64_t		size;
	uint16_t		mode;

	trace_xrep_dinode_size(sc, dip);

	mode = be16_to_cpu(dip->di_mode);
	size = be64_to_cpu(dip->di_size);
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		/* di_size can't be nonzero for special files */
		dip->di_size = 0;
		break;
	case S_IFREG:
		/* Regular files can't be larger than 2^63-1 bytes. */
		dip->di_size = cpu_to_be64(size & ~(1ULL << 63));
		break;
	case S_IFLNK:
		/*
		 * Truncate ridiculously oversized symlinks.  If the size is
		 * zero, reset it to point to the current directory.  Both of
		 * these conditions trigger dinode verifier errors, so there
		 * is no in-core state to reset.
		 */
		if (size > XFS_SYMLINK_MAXLEN)
			dip->di_size = cpu_to_be64(XFS_SYMLINK_MAXLEN);
		else if (size == 0)
			xrep_dinode_zap_symlink(sc, dip);
		break;
	case S_IFDIR:
		/*
		 * Directories can't have a size larger than 32G.  If the size
		 * is zero, reset it to an empty directory.  Both of these
		 * conditions trigger dinode verifier errors, so there is no
		 * in-core state to reset.
		 */
		if (size > XFS_DIR2_SPACE_SIZE)
			dip->di_size = cpu_to_be64(XFS_DIR2_SPACE_SIZE);
		else if (size == 0)
			xrep_dinode_zap_dir(sc, dip);
		break;
	}
}

/* Fix extent size hints. */
STATIC void
xrep_dinode_extsize_hints(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip)
{
	struct xfs_mount	*mp = sc->mp;
	uint64_t		flags2;
	uint16_t		flags;
	uint16_t		mode;
	xfs_failaddr_t		fa;

	trace_xrep_dinode_extsize_hints(sc, dip);

	mode = be16_to_cpu(dip->di_mode);
	flags = be16_to_cpu(dip->di_flags);
	flags2 = be64_to_cpu(dip->di_flags2);

	fa = xfs_inode_validate_extsize(mp, be32_to_cpu(dip->di_extsize),
			mode, flags);
	if (fa) {
		dip->di_extsize = 0;
		dip->di_flags &= ~cpu_to_be16(XFS_DIFLAG_EXTSIZE |
					      XFS_DIFLAG_EXTSZINHERIT);
	}

	if (dip->di_version < 3)
		return;

	fa = xfs_inode_validate_cowextsize(mp, be32_to_cpu(dip->di_cowextsize),
			mode, flags, flags2);
	if (fa) {
		dip->di_cowextsize = 0;
		dip->di_flags2 &= ~cpu_to_be64(XFS_DIFLAG2_COWEXTSIZE);
	}
}

/* Count extents and blocks for an inode given an rmap. */
STATIC int
xrep_dinode_walk_rmap(
	struct xfs_btree_cur		*cur,
	struct xfs_rmap_irec		*rec,
	void				*priv)
{
	struct xrep_dinode_stats	*dis = priv;
	int				error = 0;

	if (xchk_should_terminate(dis->sc, &error))
		return error;

	/* We only care about this inode. */
	if (rec->rm_owner != dis->sc->sm->sm_ino)
		return 0;

	if (rec->rm_flags & XFS_RMAP_ATTR_FORK) {
		dis->attr_blocks += rec->rm_blockcount;
		if (!(rec->rm_flags & XFS_RMAP_BMBT_BLOCK))
			dis->attr_extents++;

		return 0;
	}

	dis->data_blocks += rec->rm_blockcount;
	if (!(rec->rm_flags & XFS_RMAP_BMBT_BLOCK)) {
		dis->data_extents++;

		if (rec->rm_offset == 0 &&
		    !(rec->rm_flags & XFS_RMAP_UNWRITTEN)) {
			if (dis->block0 != NULLFSBLOCK)
				return -EFSCORRUPTED;
			dis->block0 = rec->rm_startblock;
		}
	}

	return 0;
}

/* Count extents and blocks for an inode from all AG rmap data. */
STATIC int
xrep_dinode_count_ag_rmaps(
	struct xrep_dinode_stats	*dis,
	xfs_agnumber_t			agno)
{
	struct xfs_btree_cur		*cur;
	struct xfs_buf			*agf;
	int				error;

	error = xfs_alloc_read_agf(dis->sc->mp, dis->sc->tp, agno, 0, &agf);
	if (error)
		return error;

	cur = xfs_rmapbt_init_cursor(dis->sc->mp, dis->sc->tp, agf, agno);
	error = xfs_rmap_query_all(cur, xrep_dinode_walk_rmap, dis);
	xfs_btree_del_cursor(cur, error);
	xfs_trans_brelse(dis->sc->tp, agf);
	return error;
}

/* Count extents and blocks for a given inode from all rmap data. */
STATIC int
xrep_dinode_count_rmaps(
	struct xrep_dinode_stats	*dis)
{
	xfs_agnumber_t			agno;
	int				error;

	if (!xfs_sb_version_hasrmapbt(&dis->sc->mp->m_sb) ||
	    xfs_sb_version_hasrealtime(&dis->sc->mp->m_sb))
		return -EOPNOTSUPP;

	for (agno = 0; agno < dis->sc->mp->m_sb.sb_agcount; agno++) {
		error = xrep_dinode_count_ag_rmaps(dis, agno);
		if (error)
			return error;
	}

	/* Can't have extents on both the rt and the data device. */
	if (dis->data_extents && dis->rt_extents)
		return -EFSCORRUPTED;

	trace_xrep_dinode_count_rmaps(dis->sc,
			dis->data_blocks, dis->rt_blocks, dis->attr_blocks,
			dis->data_extents, dis->rt_extents, dis->attr_extents,
			dis->block0);
	return 0;
}

/* Return true if this extents-format ifork looks like garbage. */
STATIC bool
xrep_dinode_bad_extents_fork(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip,
	int			dfork_size,
	int			whichfork)
{
	struct xfs_bmbt_irec	new;
	struct xfs_bmbt_rec	*dp;
	bool			isrt;
	int			i;
	int			nex;
	int			fork_size;

	nex = XFS_DFORK_NEXTENTS(dip, whichfork);
	fork_size = nex * sizeof(struct xfs_bmbt_rec);
	if (fork_size < 0 || fork_size > dfork_size)
		return true;
	if (whichfork == XFS_ATTR_FORK && nex > ((uint16_t)-1U))
		return true;
	dp = XFS_DFORK_PTR(dip, whichfork);

	isrt = dip->di_flags & cpu_to_be16(XFS_DIFLAG_REALTIME);
	for (i = 0; i < nex; i++, dp++) {
		xfs_failaddr_t	fa;

		xfs_bmbt_disk_get_all(dp, &new);
		fa = xfs_bmap_validate_extent_raw(sc->mp, isrt, whichfork,
				&new);
		if (fa)
			return true;
	}

	return false;
}

/* Return true if this btree-format ifork looks like garbage. */
STATIC bool
xrep_dinode_bad_btree_fork(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip,
	int			dfork_size,
	int			whichfork)
{
	struct xfs_bmdr_block	*dfp;
	int			nrecs;
	int			level;

	if (XFS_DFORK_NEXTENTS(dip, whichfork) <=
			dfork_size / sizeof(struct xfs_bmbt_rec))
		return true;

	if (dfork_size < sizeof(struct xfs_bmdr_block))
		return true;

	dfp = XFS_DFORK_PTR(dip, whichfork);
	nrecs = be16_to_cpu(dfp->bb_numrecs);
	level = be16_to_cpu(dfp->bb_level);

	if (nrecs == 0 || XFS_BMDR_SPACE_CALC(nrecs) > dfork_size)
		return true;
	if (level == 0 || level >= XFS_BM_MAXLEVELS(sc->mp, whichfork))
		return true;
	return false;
}

/*
 * Check the data fork for things that will fail the ifork verifiers or the
 * ifork formatters.
 */
STATIC bool
xrep_dinode_check_dfork(
	struct xfs_scrub	*sc,
	struct xfs_dinode	*dip,
	uint16_t		mode)
{
	uint64_t		size;
	unsigned int		fmt;
	int			dfork_size;

	fmt = XFS_DFORK_FORMAT(dip, XFS_DATA_FORK);
	size = be64_to_cpu(dip->di_size);
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		if (fmt != XFS_DINODE_FMT_DEV)
			return true;
		break;
	case S_IFREG:
		if (fmt == XFS_DINODE_FMT_LOCAL)
			return true;
		/* fall through */
	case S_IFLNK:
	case S_IFDIR:
		switch (fmt) {
		case XFS_DINODE_FMT_LOCAL:
		case XFS_DINODE_FMT_EXTENTS:
		case XFS_DINODE_FMT_BTREE:
			break;
		default:
			return true;
		}
		break;
	default:
		return true;
	}
	dfork_size = XFS_DFORK_SIZE(dip, sc->mp, XFS_DATA_FORK);
	switch (fmt) {
	case XFS_DINODE_FMT_DEV:
		break;
	case XFS_DINODE_FMT_LOCAL:
		if (size > dfork_size)
			return true;
		break;
	case XFS_DINODE_FMT_EXTENTS:
		if (xrep_dinode_bad_extents_fork(sc, dip, dfork_size,
				XFS_DATA_FORK))
			return true;
		break;
	case XFS_DINODE_FMT_BTREE:
		if (xrep_dinode_bad_btree_fork(sc, dip, dfork_size,
				XFS_DATA_FORK))
			return true;
		break;
	default:
		return true;
	}

	return false;
}

/* Reset the data fork to something sane. */
STATIC void
xrep_dinode_zap_dfork(
	struct xfs_scrub		*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode,
	struct xrep_dinode_stats	*dis)
{
	trace_xrep_dinode_zap_dfork(sc, dip);

	dip->di_nextents = 0;

	/* Special files always get reset to DEV */
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		dip->di_format = XFS_DINODE_FMT_DEV;
		dip->di_size = 0;
		return;
	}

	/*
	 * If we have data extents, reset to an empty map and hope the user
	 * will run the bmapbtd checker next.
	 */
	if (dis->data_extents || dis->rt_extents || S_ISREG(mode)) {
		dip->di_format = XFS_DINODE_FMT_EXTENTS;
		return;
	}

	/* Otherwise, reset the local format to the minimum. */
	switch (mode & S_IFMT) {
	case S_IFLNK:
		xrep_dinode_zap_symlink(sc, dip);
		break;
	case S_IFDIR:
		xrep_dinode_zap_dir(sc, dip);
		break;
	}
}

/*
 * Check the attr fork for things that will fail the ifork verifiers or the
 * ifork formatters.
 */
STATIC bool
xrep_dinode_check_afork(
	struct xfs_scrub		*sc,
	struct xfs_dinode		*dip)
{
	struct xfs_attr_shortform	*sfp;
	int				size;

	if (XFS_DFORK_BOFF(dip) == 0)
		return dip->di_aformat != XFS_DINODE_FMT_EXTENTS ||
		       dip->di_anextents != 0;

	size = XFS_DFORK_SIZE(dip, sc->mp, XFS_ATTR_FORK);
	switch (XFS_DFORK_FORMAT(dip, XFS_ATTR_FORK)) {
	case XFS_DINODE_FMT_LOCAL:
		sfp = XFS_DFORK_PTR(dip, XFS_ATTR_FORK);
		return xfs_attr_shortform_verify_struct(sfp, size) != NULL;
	case XFS_DINODE_FMT_EXTENTS:
		if (xrep_dinode_bad_extents_fork(sc, dip, size, XFS_ATTR_FORK))
			return true;
		break;
	case XFS_DINODE_FMT_BTREE:
		if (xrep_dinode_bad_btree_fork(sc, dip, size, XFS_ATTR_FORK))
			return true;
		break;
	default:
		return true;
	}

	return false;
}

/*
 * Reset the attr fork to empty.  Since the attr fork could have contained
 * ACLs, make the file readable only by root.
 */
STATIC void
xrep_dinode_zap_afork(
	struct xfs_scrub		*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode,
	struct xrep_dinode_stats	*dis)
{
	trace_xrep_dinode_zap_afork(sc, dip);

	dip->di_aformat = XFS_DINODE_FMT_EXTENTS;
	dip->di_anextents = 0;

	dip->di_forkoff = 0;
	dip->di_mode = cpu_to_be16(mode & ~0777);
	dip->di_uid = 0;
	dip->di_gid = 0;
}

/* Make sure the fork offset is a sensible value. */
STATIC void
xrep_dinode_ensure_forkoff(
	struct xfs_scrub		*sc,
	struct xfs_dinode		*dip,
	uint16_t			mode,
	struct xrep_dinode_stats	*dis)
{
	struct xfs_bmdr_block		*bmdr;
	size_t				bmdr_minsz = XFS_BMDR_SPACE_CALC(1);
	unsigned int			lit_sz = XFS_LITINO(sc->mp);
	unsigned int			afork_min, dfork_min;

	trace_xrep_dinode_ensure_forkoff(sc, dip);

	/*
	 * Before calling this function, xrep_dinode_core ensured that both
	 * forks actually fit inside their respective literal areas.  If this
	 * was not the case, the fork was reset to FMT_EXTENTS with zero
	 * records.  If the rmapbt scan found attr or data fork blocks, this
	 * will be noted in the dinode_stats, and we must leave enough room
	 * for the bmap repair code to reconstruct the mapping structure.
	 *
	 * First, compute the minimum space required for the attr fork.
	 */
	switch (dip->di_aformat) {
	case XFS_DINODE_FMT_LOCAL:
		/*
		 * If we still have a shortform xattr structure at all, that
		 * means the attr fork area was exactly large enough to fit
		 * the sf structure.
		 */
		afork_min = XFS_DFORK_SIZE(dip, sc->mp, XFS_ATTR_FORK);
		break;
	case XFS_DINODE_FMT_EXTENTS:
		if (dip->di_anextents) {
			/*
			 * We must maintain sufficient space to hold the entire
			 * extent map array in the data fork.  Note that we
			 * previously zapped the fork if it had no chance of
			 * fitting in the inode.
			 */
			afork_min = sizeof(struct xfs_bmbt_rec) *
						be16_to_cpu(dip->di_anextents);
		} else if (dis->attr_extents > 0) {
			/*
			 * The attr fork thinks it has zero extents, but we
			 * found some xattr extents.  We need to leave enough
			 * empty space here so that the incore attr fork will
			 * get created (and hence trigger the attr fork bmap
			 * repairer).
			 */
			afork_min = bmdr_minsz;
		} else {
			/* No extents on disk or found in rmapbt. */
			afork_min = 0;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		/* Must have space for btree header and key/pointers. */
		bmdr = XFS_DFORK_PTR(dip, XFS_ATTR_FORK);
		afork_min = XFS_BMAP_BROOT_SPACE(sc->mp, bmdr);
		break;
	default:
		/* We should never see any other formats. */
		afork_min = 0;
		break;
	}

	/* Compute the minimum space required for the data fork. */
	switch (dip->di_format) {
	case XFS_DINODE_FMT_DEV:
		dfork_min = sizeof(__be32);
		break;
	case XFS_DINODE_FMT_UUID:
		dfork_min = sizeof(uuid_t);
		break;
	case XFS_DINODE_FMT_LOCAL:
		/*
		 * If we still have a shortform data fork at all, that means
		 * the data fork area was large enough to fit whatever was in
		 * there.
		 */
		dfork_min = be64_to_cpu(dip->di_size);
		break;
	case XFS_DINODE_FMT_EXTENTS:
		if (dip->di_nextents) {
			/*
			 * We must maintain sufficient space to hold the entire
			 * extent map array in the data fork.  Note that we
			 * previously zapped the fork if it had no chance of
			 * fitting in the inode.
			 */
			dfork_min = sizeof(struct xfs_bmbt_rec) *
						be32_to_cpu(dip->di_nextents);
		} else if (dis->data_extents > 0 || dis->rt_extents > 0) {
			/*
			 * The data fork thinks it has zero extents, but we
			 * found some data extents.  We need to leave enough
			 * empty space here so that the the data fork bmap
			 * repair will recover the mappings.
			 */
			dfork_min = bmdr_minsz;
		} else {
			/* No extents on disk or found in rmapbt. */
			dfork_min = 0;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		/* Must have space for btree header and key/pointers. */
		bmdr = XFS_DFORK_PTR(dip, XFS_DATA_FORK);
		dfork_min = XFS_BMAP_BROOT_SPACE(sc->mp, bmdr);
		break;
	default:
		dfork_min = 0;
		break;
	}

	/*
	 * Round all values up to the nearest 8 bytes, because that is the
	 * precision of di_forkoff.
	 */
	afork_min = roundup(afork_min, 8);
	dfork_min = roundup(dfork_min, 8);
	bmdr_minsz = roundup(bmdr_minsz, 8);

	ASSERT(dfork_min <= lit_sz);
	ASSERT(afork_min <= lit_sz);

	/*
	 * If the data fork was zapped and we don't have enough space for the
	 * recovery fork, move the attr fork up.
	 */
	if (dip->di_format == XFS_DINODE_FMT_EXTENTS &&
	    dip->di_nextents == 0 &&
	    (dis->data_extents > 0 || dis->rt_extents > 0) &&
	    bmdr_minsz > XFS_DFORK_DSIZE(dip, sc->mp)) {
		if (bmdr_minsz + afork_min > lit_sz) {
			/*
			 * The attr for and the stub fork we need to recover
			 * the data fork won't both fit.  Zap the attr fork.
			 */
			xrep_dinode_zap_afork(sc, dip, mode, dis);
			afork_min = bmdr_minsz;
		} else {
			void 	*before, *after;

			/* Otherwise, just slide the attr fork up. */
			before = XFS_DFORK_APTR(dip);
			dip->di_forkoff = bmdr_minsz >> 3;
			after = XFS_DFORK_APTR(dip);
			memmove(after, before, XFS_DFORK_ASIZE(dip, sc->mp));
		}
	}

	/*
	 * If the attr fork was zapped and we don't have enough space for the
	 * recovery fork, move the attr fork down.
	 */
	if (dip->di_aformat == XFS_DINODE_FMT_EXTENTS &&
	    dip->di_anextents == 0 &&
	    dis->attr_extents > 0 &&
	    bmdr_minsz > XFS_DFORK_ASIZE(dip, sc->mp)) {
		if (dip->di_format == XFS_DINODE_FMT_BTREE) {
			/*
			 * If the data fork is in btree format then we can't
			 * adjust forkoff because that runs the risk of
			 * violating the extents/btree format transition rules.
			 */
		} else if (bmdr_minsz + dfork_min > lit_sz) {
			/*
			 * If we can't move the attr fork, too bad, we lose the
			 * attr fork and leak its blocks.
			 */
			xrep_dinode_zap_afork(sc, dip, mode, dis);
		} else {
			/*
			 * Otherwise, just slide the attr fork down.  The attr
			 * fork is empty, so we don't have any old contents to
			 * move here.
			 */
			dip->di_forkoff = (lit_sz - bmdr_minsz) >> 3;
		}
	}
}

/*
 * Zap the data/attr forks if we spot anything that isn't going to pass the
 * ifork verifiers or the ifork formatters, because we need to get the inode
 * into good enough shape that the higher level repair functions can run.
 */
STATIC void
xrep_dinode_zap_forks(
	struct xfs_scrub		*sc,
	struct xfs_dinode		*dip,
	struct xrep_dinode_stats	*dis)
{
	uint16_t			mode;
	bool				zap_datafork = false;
	bool				zap_attrfork = false;

	trace_xrep_dinode_zap_forks(sc, dip);

	mode = be16_to_cpu(dip->di_mode);

	/* Inode counters don't make sense? */
	if (be32_to_cpu(dip->di_nextents) > be64_to_cpu(dip->di_nblocks))
		zap_datafork = true;
	if (be16_to_cpu(dip->di_anextents) > be64_to_cpu(dip->di_nblocks))
		zap_attrfork = true;
	if (be32_to_cpu(dip->di_nextents) + be16_to_cpu(dip->di_anextents) >
			be64_to_cpu(dip->di_nblocks))
		zap_datafork = zap_attrfork = true;

	if (!zap_datafork)
		zap_datafork = xrep_dinode_check_dfork(sc, dip, mode);
	if (!zap_attrfork)
		zap_attrfork = xrep_dinode_check_afork(sc, dip);

	/* Zap whatever's bad. */
	if (zap_attrfork)
		xrep_dinode_zap_afork(sc, dip, mode, dis);
	if (zap_datafork)
		xrep_dinode_zap_dfork(sc, dip, mode, dis);
	xrep_dinode_ensure_forkoff(sc, dip, mode, dis);
	dip->di_nblocks = 0;
	if (!zap_attrfork)
		be64_add_cpu(&dip->di_nblocks, dis->attr_blocks);
	if (!zap_datafork) {
		be64_add_cpu(&dip->di_nblocks, dis->data_blocks);
		be64_add_cpu(&dip->di_nblocks, dis->rt_blocks);
	}
}

/* Inode didn't pass verifiers, so fix the raw buffer and retry iget. */
STATIC int
xrep_dinode_core(
	struct xfs_scrub	*sc)
{
	struct xrep_dinode_stats dis = {
		.sc		= sc,
		.block0		= NULLFSBLOCK,
	};
	struct xfs_imap		imap;
	struct xfs_buf		*bp;
	struct xfs_dinode	*dip;
	xfs_ino_t		ino = sc->sm->sm_ino;
	bool			inuse;
	int			error;

	/* Figure out what this inode had mapped in both forks. */
	error = xrep_dinode_count_rmaps(&dis);
	if (error)
		return error;

	/* Map & read inode. */
	error = xfs_imap(sc->mp, sc->tp, ino, &imap, XFS_IGET_UNTRUSTED);
	if (error)
		return error;

	error = xfs_trans_read_buf(sc->mp, sc->tp, sc->mp->m_ddev_targp,
			imap.im_blkno, imap.im_len, XBF_UNMAPPED, &bp, NULL);
	if (error)
		return error;

	/* Make absolutely sure this inode isn't in core. */
	error = xfs_icache_inode_is_allocated(sc->mp, sc->tp, ino, &inuse);
	if (error == 0) {
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	/* Make sure we can pass the inode buffer verifier. */
	xrep_dinode_buf(sc, bp);
	bp->b_ops = &xfs_inode_buf_ops;

	/* Fix everything the verifier will complain about. */
	dip = xfs_buf_offset(bp, imap.im_boffset);
	xrep_dinode_header(sc, dip);
	xrep_dinode_mode(sc, dip, &dis);
	xrep_dinode_flags(sc, dip, dis.rt_extents > 0);
	xrep_dinode_size(sc, dip);
	xrep_dinode_extsize_hints(sc, dip);
	xrep_dinode_zap_forks(sc, dip, &dis);

	/* Write out the inode... */
	trace_xrep_dinode_fixed(sc, dip);
	xfs_dinode_calc_crc(sc->mp, dip);
	xfs_trans_buf_set_type(sc->tp, bp, XFS_BLFT_DINO_BUF);
	xfs_trans_log_buf(sc->tp, bp, imap.im_boffset,
			imap.im_boffset + sc->mp->m_sb.sb_inodesize - 1);
	error = xfs_trans_commit(sc->tp);
	if (error)
		return error;
	sc->tp = NULL;

	/* ...and reload it? */
	error = xfs_iget(sc->mp, sc->tp, ino,
			XFS_IGET_UNTRUSTED | XFS_IGET_DONTCACHE, 0, &sc->ip);
	if (error)
		return error;
	sc->ilock_flags = XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL;
	xfs_ilock(sc->ip, sc->ilock_flags);
	error = xchk_trans_alloc(sc, 0);
	if (error)
		return error;
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);

	return 0;
}

/* Fix everything xfs_dinode_verify cares about. */
STATIC int
xrep_dinode_problems(
	struct xfs_scrub	*sc)
{
	int			error;

	error = xrep_dinode_core(sc);
	if (error)
		return error;

	/* We had to fix a totally busted inode, schedule quotacheck. */
	if (XFS_IS_UQUOTA_ON(sc->mp))
		xrep_force_quotacheck(sc, XFS_DQTYPE_USER);
	if (XFS_IS_GQUOTA_ON(sc->mp))
		xrep_force_quotacheck(sc, XFS_DQTYPE_GROUP);
	if (XFS_IS_PQUOTA_ON(sc->mp))
		xrep_force_quotacheck(sc, XFS_DQTYPE_PROJ);

	return 0;
}

/*
 * Fix problems that the verifiers don't care about.  In general these are
 * errors that don't cause problems elsewhere in the kernel that we can easily
 * detect, so we don't check them all that rigorously.
 */

/* Make sure block and extent counts are ok. */
STATIC int
xrep_inode_blockcounts(
	struct xfs_scrub	*sc)
{
	struct xfs_ifork	*ifp;
	xfs_filblks_t		count;
	xfs_filblks_t		acount;
	xfs_extnum_t		nextents;
	int			error;

	trace_xrep_inode_blockcounts(sc);

	/* Set data fork counters from the data fork mappings. */
	error = xfs_bmap_count_blocks(sc->tp, sc->ip, XFS_DATA_FORK,
			&nextents, &count);
	if (error)
		return error;
	if (XFS_IS_REALTIME_INODE(sc->ip)) {
		if (count >= sc->mp->m_sb.sb_rblocks)
			return -EFSCORRUPTED;
	} else if (!xfs_sb_version_hasreflink(&sc->mp->m_sb)) {
		if (count >= sc->mp->m_sb.sb_dblocks)
			return -EFSCORRUPTED;
	}
	sc->ip->i_df.if_nextents = nextents;

	/* Set attr fork counters from the attr fork mappings. */
	ifp = XFS_IFORK_PTR(sc->ip, XFS_ATTR_FORK);
	if (ifp) {
		error = xfs_bmap_count_blocks(sc->tp, sc->ip, XFS_ATTR_FORK,
				&nextents, &acount);
		if (error)
			return error;
		if (count >= sc->mp->m_sb.sb_dblocks)
			return -EFSCORRUPTED;
		if (nextents >= MAXAEXTNUM)
			return -EFSCORRUPTED;
		ifp->if_nextents = nextents;
	} else {
		acount = 0;
	}

	sc->ip->i_nblocks = count + acount;
	return 0;
}

/* Check for invalid uid/gid/prid. */
STATIC void
xrep_inode_ids(
	struct xfs_scrub	*sc)
{
	trace_xrep_inode_ids(sc);

	if (i_uid_read(VFS_I(sc->ip)) == -1U) {
		i_uid_write(VFS_I(sc->ip), 0);
		VFS_I(sc->ip)->i_mode &= ~(S_ISUID | S_ISGID);
		if (XFS_IS_UQUOTA_ON(sc->mp))
			xrep_force_quotacheck(sc, XFS_DQTYPE_USER);
	}

	if (i_gid_read(VFS_I(sc->ip)) == -1U) {
		i_gid_write(VFS_I(sc->ip), 0);
		VFS_I(sc->ip)->i_mode &= ~(S_ISUID | S_ISGID);
		if (XFS_IS_GQUOTA_ON(sc->mp))
			xrep_force_quotacheck(sc, XFS_DQTYPE_GROUP);
	}

	if (sc->ip->i_projid == -1U) {
		sc->ip->i_projid = 0;
		if (XFS_IS_PQUOTA_ON(sc->mp))
			xrep_force_quotacheck(sc, XFS_DQTYPE_PROJ);
	}
}

static inline void
xrep_clamp_nsec(
	struct timespec64	*ts)
{
	ts->tv_nsec = clamp_t(long, ts->tv_nsec, 0, NSEC_PER_SEC);
}

/* Nanosecond counters can't have more than 1 billion. */
STATIC void
xrep_inode_timestamps(
	struct xfs_inode	*ip)
{
	xrep_clamp_nsec(&VFS_I(ip)->i_atime);
	xrep_clamp_nsec(&VFS_I(ip)->i_mtime);
	xrep_clamp_nsec(&VFS_I(ip)->i_ctime);
	xrep_clamp_nsec(&ip->i_crtime);
}

/* Fix inode flags that don't make sense together. */
STATIC void
xrep_inode_flags(
	struct xfs_scrub	*sc)
{
	uint16_t		mode;

	trace_xrep_inode_flags(sc);

	mode = VFS_I(sc->ip)->i_mode;

	/* Clear junk flags */
	if (sc->ip->i_diflags & ~XFS_DIFLAG_ANY)
		sc->ip->i_diflags &= ~XFS_DIFLAG_ANY;

	/* NEWRTBM only applies to realtime bitmaps */
	if (sc->ip->i_ino == sc->mp->m_sb.sb_rbmino)
		sc->ip->i_diflags |= XFS_DIFLAG_NEWRTBM;
	else
		sc->ip->i_diflags &= ~XFS_DIFLAG_NEWRTBM;

	/* These only make sense for directories. */
	if (!S_ISDIR(mode))
		sc->ip->i_diflags &= ~(XFS_DIFLAG_RTINHERIT |
					  XFS_DIFLAG_EXTSZINHERIT |
					  XFS_DIFLAG_PROJINHERIT |
					  XFS_DIFLAG_NOSYMLINKS);

	/* These only make sense for files. */
	if (!S_ISREG(mode))
		sc->ip->i_diflags &= ~(XFS_DIFLAG_REALTIME |
					  XFS_DIFLAG_EXTSIZE);

	/* These only make sense for non-rt files. */
	if (sc->ip->i_diflags & XFS_DIFLAG_REALTIME)
		sc->ip->i_diflags &= ~XFS_DIFLAG_FILESTREAM;

	/* Immutable and append only?  Drop the append. */
	if ((sc->ip->i_diflags & XFS_DIFLAG_IMMUTABLE) &&
	    (sc->ip->i_diflags & XFS_DIFLAG_APPEND))
		sc->ip->i_diflags &= ~XFS_DIFLAG_APPEND;

	/* Clear junk flags. */
	if (sc->ip->i_diflags2 & ~XFS_DIFLAG2_ANY)
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_ANY;

	/* No reflink flag unless we support it and it's a file. */
	if (!xfs_sb_version_hasreflink(&sc->mp->m_sb) ||
	    !S_ISREG(mode))
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;

	/* DAX only applies to files and dirs. */
	if (!(S_ISREG(mode) || S_ISDIR(mode)))
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_DAX;

	/* No reflink files on the realtime device. */
	if (sc->ip->i_diflags & XFS_DIFLAG_REALTIME)
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;

	/* No mixing reflink and DAX yet. */
	if (sc->ip->i_diflags2 & XFS_DIFLAG2_REFLINK)
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_DAX;
}

/*
 * Fix size problems with block/node format directories.  If we fail to find
 * the extent list, just bail out and let the bmapbtd repair functions clean
 * up that mess.
 */
STATIC void
xrep_inode_blockdir_size(
	struct xfs_scrub	*sc)
{
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	struct xfs_ifork	*ifp;
	xfs_fileoff_t		off;
	int			error;

	trace_xrep_inode_blockdir_size(sc);

	/* Find the last block before 32G; this is the dir size. */
	error = xfs_iread_extents(sc->tp, sc->ip, XFS_DATA_FORK);
	if (error)
		return;

	ifp = XFS_IFORK_PTR(sc->ip, XFS_DATA_FORK);
	off = XFS_B_TO_FSB(sc->mp, XFS_DIR2_SPACE_SIZE);
	if (!xfs_iext_lookup_extent_before(sc->ip, ifp, &off, &icur, &got)) {
		/* zero-extents directory? */
		return;
	}

	off = got.br_startoff + got.br_blockcount;
	sc->ip->i_disk_size = min_t(loff_t, XFS_DIR2_SPACE_SIZE,
			XFS_FSB_TO_B(sc->mp, off));
}

/* Fix size problems with short format directories. */
STATIC void
xrep_inode_sfdir_size(
	struct xfs_scrub	*sc)
{
	struct xfs_ifork	*ifp;

	trace_xrep_inode_sfdir_size(sc);

	ifp = XFS_IFORK_PTR(sc->ip, XFS_DATA_FORK);
	sc->ip->i_disk_size = ifp->if_bytes;
}

/*
 * Fix any irregularities in an inode's size now that we can iterate extent
 * maps and access other regular inode data.
 */
STATIC void
xrep_inode_size(
	struct xfs_scrub	*sc)
{
	trace_xrep_inode_size(sc);

	/*
	 * Currently we only support fixing size on extents or btree format
	 * directories.  Files can be any size and sizes for the other inode
	 * special types are fixed by xrep_dinode_size.
	 */
	if (!S_ISDIR(VFS_I(sc->ip)->i_mode))
		return;
	switch (sc->ip->i_df.if_format) {
	case XFS_DINODE_FMT_EXTENTS:
	case XFS_DINODE_FMT_BTREE:
		xrep_inode_blockdir_size(sc);
		break;
	case XFS_DINODE_FMT_LOCAL:
		xrep_inode_sfdir_size(sc);
		break;
	}
}

/* Fix any irregularities in an inode that the verifiers don't catch. */
STATIC int
xrep_inode_problems(
	struct xfs_scrub	*sc)
{
	int			error;

	error = xrep_inode_blockcounts(sc);
	if (error)
		return error;
	xrep_inode_timestamps(sc->ip);
	xrep_inode_flags(sc);
	xrep_inode_ids(sc);
	xrep_inode_size(sc);

	trace_xrep_inode_fixed(sc);
	xfs_trans_log_inode(sc->tp, sc->ip, XFS_ILOG_CORE);
	return xrep_roll_trans(sc);
}

/* Repair an inode's fields. */
int
xrep_inode(
	struct xfs_scrub	*sc)
{
	int			error = 0;

	/*
	 * No inode?  That means we failed the _iget verifiers.  Repair all
	 * the things that the inode verifiers care about, then retry _iget.
	 */
	if (!sc->ip) {
		error = xrep_dinode_problems(sc);
		if (error)
			return error;

		/* By this point we had better have a working incore inode. */
		if (!sc->ip)
			return -EFSCORRUPTED;
	}

	xfs_trans_ijoin(sc->tp, sc->ip, 0);

	/* If we found corruption of any kind, try to fix it. */
	if ((sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT) ||
	    (sc->sm->sm_flags & XFS_SCRUB_OFLAG_XCORRUPT)) {
		error = xrep_inode_problems(sc);
		if (error)
			return error;
	}

	/* See if we can clear the reflink flag. */
	if (xfs_is_reflink_inode(sc->ip))
		return xfs_reflink_clear_inode_flag(sc->ip, &sc->tp);

	return 0;
}
