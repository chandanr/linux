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
#include "xfs_inode_fork.h"
#include "xfs_symlink.h"
#include "xfs_bmap.h"
#include "xfs_quota.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_bmap_btree.h"
#include "xfs_trans_space.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/*
 * Symbolic Link Repair
 * ====================
 *
 * There's not much we can do to repair symbolic links -- we truncate them to
 * the first NULL byte and reinitialize the target.  Zero-length symlinks are
 * turned into links to the current dir.
 */

/* Try to salvage the pathname from rmt blocks. */
STATIC int
xrep_symlink_salvage_remote(
	struct xfs_scrub	*sc)
{
	struct xfs_bmbt_irec	mval[XFS_SYMLINK_MAPS];
	struct xfs_inode	*ip = sc->ip;
	struct xfs_buf		*bp;
	char			*target_buf = sc->buf;
	xfs_failaddr_t		fa;
	xfs_filblks_t		fsblocks;
	xfs_daddr_t		d;
	loff_t			len;
	loff_t			offset;
	unsigned int		byte_cnt;
	bool			magic_ok;
	bool			hdr_ok;
	int			n;
	int			nmaps = XFS_SYMLINK_MAPS;
	int			error;

	/* We'll only read until the buffer is full. */
	len = max_t(loff_t, ip->i_disk_size, XFS_SYMLINK_MAXLEN);
	fsblocks = xfs_symlink_blocks(sc->mp, len);
	error = xfs_bmapi_read(ip, 0, fsblocks, mval, &nmaps, 0);
	if (error)
		return error;

	offset = 0;
	for (n = 0; n < nmaps; n++) {
		struct xfs_dsymlink_hdr	*dsl;

		d = XFS_FSB_TO_DADDR(sc->mp, mval[n].br_startblock);

		/* Read the rmt block.  We'll run the verifiers manually. */
		error = xfs_trans_read_buf(sc->mp, sc->tp, sc->mp->m_ddev_targp,
				d, XFS_FSB_TO_BB(sc->mp, mval[n].br_blockcount),
				0, &bp, NULL);
		if (error)
			return error;
		bp->b_ops = &xfs_symlink_buf_ops;

		/* How many bytes do we expect to get out of this buffer? */
		byte_cnt = XFS_FSB_TO_B(sc->mp, mval[n].br_blockcount);
		byte_cnt = XFS_SYMLINK_BUF_SPACE(sc->mp, byte_cnt);
		byte_cnt = min_t(unsigned int, byte_cnt, len);

		/*
		 * See if the verifiers accept this block.  We're willing to
		 * salvage if the if the offset/byte/ino are ok and either the
		 * verifier passed or the magic is ok.  Anything else and we
		 * stop dead in our tracks.
		 */
		fa = bp->b_ops->verify_struct(bp);
		dsl = bp->b_addr;
		magic_ok = dsl->sl_magic == cpu_to_be32(XFS_SYMLINK_MAGIC);
		hdr_ok = xfs_symlink_hdr_ok(ip->i_ino, offset, byte_cnt, bp);
		if (!hdr_ok || (fa != NULL && !magic_ok))
			break;

		memcpy(target_buf + offset, dsl + 1, byte_cnt);

		len -= byte_cnt;
		offset += byte_cnt;
	}

	/* Ensure we have a zero at the end, and /some/ contents. */
	if (offset == 0)
		sprintf(target_buf, ".");
	else
		target_buf[offset] = 0;
	return 0;
}

/*
 * Try to salvage an inline symlink's contents.  Empty symlinks become a link
 * to the current directory.
 */
STATIC void
xrep_symlink_salvage_inline(
	struct xfs_scrub	*sc)
{
	struct xfs_inode	*ip = sc->ip;
	struct xfs_ifork	*ifp;

	ifp = XFS_IFORK_PTR(ip, XFS_DATA_FORK);
	if (ifp->if_u1.if_data)
		strncpy(sc->buf, ifp->if_u1.if_data, XFS_IFORK_DSIZE(ip));
	if (strlen(sc->buf) == 0)
		sprintf(sc->buf, ".");
}

/* Reset an inline symlink to its fresh configuration. */
STATIC void
xrep_symlink_truncate_inline(
	struct xfs_inode	*ip)
{
	struct xfs_ifork	*ifp = XFS_IFORK_PTR(ip, XFS_DATA_FORK);

	xfs_idestroy_fork(ifp);
	memset(ifp, 0, sizeof(struct xfs_ifork));
	ifp->if_format = XFS_DINODE_FMT_EXTENTS;
	ifp->if_nextents = 0;
}

/*
 * Salvage an inline symlink's contents and reset data fork.
 * Returns with the inode joined to the transaction.
 */
STATIC int
xrep_symlink_inline(
	struct xfs_scrub	*sc)
{
	/* Salvage whatever link target information we can find. */
	xrep_symlink_salvage_inline(sc);

	/* Truncate the symlink. */
	xrep_symlink_truncate_inline(sc->ip);

	xfs_trans_ijoin(sc->tp, sc->ip, 0);
	return 0;
}

/*
 * Salvage an inline symlink's contents and reset data fork.
 * Returns with the inode joined to the transaction.
 */
STATIC int
xrep_symlink_remote(
	struct xfs_scrub	*sc)
{
	int			error;

	/* Salvage whatever link target information we can find. */
	error = xrep_symlink_salvage_remote(sc);
	if (error)
		return error;

	/* Truncate the symlink. */
	xfs_trans_ijoin(sc->tp, sc->ip, 0);
	return xfs_itruncate_extents(&sc->tp, sc->ip, XFS_DATA_FORK, 0);
}

/*
 * Reinitialize a link target.  Caller must ensure the inode is joined to
 * the transaction.
 */
STATIC int
xrep_symlink_reinitialize(
	struct xfs_scrub	*sc)
{
	xfs_fsblock_t		fs_blocks;
	unsigned int		target_len;
	unsigned int		resblks;
	unsigned int		quota_flags = XFS_QMOPT_RES_REGBLKS;
	int			error;

	/* How many blocks do we need? */
	target_len = strlen(sc->buf);
	ASSERT(target_len != 0);
	if (target_len == 0 || target_len > XFS_SYMLINK_MAXLEN)
		return -EFSCORRUPTED;

	if (sc->flags & XCHK_TRY_HARDER)
		quota_flags |= XFS_QMOPT_FORCE_RES;

	/* Set up to reinitialize the target. */
	fs_blocks = xfs_symlink_blocks(sc->mp, target_len);
	resblks = XFS_SYMLINK_SPACE_RES(sc->mp, target_len, fs_blocks);
	error = xfs_trans_reserve_quota_nblks(sc->tp, sc->ip, resblks, 0,
			quota_flags);
	if (error == -EDQUOT || error == -ENOSPC) {
		/* Let xchk_teardown release everything, and try harder. */
		return -EDEADLOCK;
	}
	if (error)
		return error;

	/* Try to write the new target back out. */
	error = xfs_symlink_write_target(sc->tp, sc->ip, sc->buf, target_len,
			fs_blocks, resblks);
	if (error)
		return error;

	/* Finish up any block mapping activities. */
	return xfs_defer_finish(&sc->tp);
}

/* Repair a symbolic link. */
int
xrep_symlink(
	struct xfs_scrub	*sc)
{
	int			error;

	error = xfs_qm_dqattach_locked(sc->ip, false);
	if (error)
		return error;

	/* Salvage whatever we can of the target. */
	*((char *)sc->buf) = 0;
	if (sc->ip->i_df.if_format == XFS_DINODE_FMT_LOCAL)
		error = xrep_symlink_inline(sc);
	else
		error = xrep_symlink_remote(sc);
	if (error)
		return error;

	/* Now reset the target. */
	return xrep_symlink_reinitialize(sc);
}
