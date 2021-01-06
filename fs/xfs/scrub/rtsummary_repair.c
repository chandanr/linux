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
#include "xfs_btree.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_rtalloc.h"
#include "xfs_inode.h"
#include "xfs_bit.h"
#include "xfs_bmap.h"
#include "xfs_swapext.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/* Repair the realtime summary. */
int
xrep_rtsummary(
	struct xfs_scrub	*sc)
{
	struct xfs_swapext_req	req = { .flags = 0 };
	int			error;

	/* Make sure any problems with the fork are fixed. */
	error = xrep_metadata_inode_forks(sc);
	if (error)
		return error;

	/*
	 * Trylock the temporary file.  We had better be the only ones holding
	 * onto this inode...
	 */
	if (!xfs_ilock_nowait(sc->tempip, XFS_ILOCK_EXCL))
		return -EAGAIN;
	sc->temp_ilock_flags = XFS_ILOCK_EXCL;

	/* Make sure we have space allocated for the entire summary file. */
	xfs_trans_ijoin(sc->tp, sc->ip, 0);
	xfs_trans_ijoin(sc->tp, sc->tempip, 0);
	error = xrep_fallocate(sc, 0, XFS_B_TO_FSB(sc->mp, sc->mp->m_rsumsize));
	if (error)
		return error;

	/* Copy the rtsummary file that we generated. */
	error = xrep_set_file_contents(sc, &xfs_rtbuf_ops,
			XFS_BLFT_RTSUMMARY_BUF, sc->mp->m_rsumsize);
	if (error)
		return error;

	/* Now swap the extents. */
	req.ip1 = sc->tempip;
	req.ip2 = sc->ip;
	req.whichfork = XFS_DATA_FORK;
	req.blockcount = XFS_B_TO_FSB(sc->mp, sc->mp->m_rsumsize);
	return xfs_swapext(&sc->tp, &req);
}
