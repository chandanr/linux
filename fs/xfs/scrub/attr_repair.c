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
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_dir2.h"
#include "xfs_attr.h"
#include "xfs_attr_leaf.h"
#include "xfs_attr_sf.h"
#include "xfs_attr_remote.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_swapext.h"
#include "xfs_xchgrange.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/array.h"
#include "scrub/blob.h"
#include "scrub/attr.h"

/*
 * Extended Attribute Repair
 * =========================
 *
 * We repair extended attributes by reading the attribute fork blocks looking
 * for keys and values, then truncate the entire attr fork and reinsert all
 * the attributes.  Unfortunately, there's no secondary copy of most extended
 * attribute data, which means that if we blow up midway through there's
 * little we can do.
 */

struct xrep_xattr_key {
	xblob_cookie		value_cookie;
	xblob_cookie		name_cookie;
	uint			hash;
	int			flags;
	uint32_t		valuelen;
	uint16_t		namelen;
};

struct xrep_xattr {
	struct xfs_scrub	*sc;
	struct xfbma		*xattr_records;
	struct xblob		*xattr_blobs;

	/* Number of attributes that we are salvaging. */
	unsigned long long	attrs_found;
};

/* Absorb up to 8 pages of attrs before we flush them to the temp file. */
#define XREP_XATTR_SALVAGE_BYTES	(PAGE_SIZE * 8)

/*
 * Allocate enough memory to hold whatever we need to salvage an attr block.
 * Buffer contents can be preserved, unlike in the scrub counterpart to this
 * function.
 */
STATIC int
xrep_setup_xattr_buf(
	struct xfs_scrub	*sc,
	size_t			value_size,
	bool			preserve)
{
	size_t			sz;
	struct xchk_xattr_buf	*new_ab;
	struct xchk_xattr_buf	*ab = sc->buf;

	ASSERT(!preserve || ab != NULL);

	/*
	 * We need enough space to hold a bitmap for the used space within an
	 * attr block; the name of a salvaged attr; and the value of a salvaged
	 * attr.
	 */
	sz = sizeof(long) * BITS_TO_LONGS(sc->mp->m_attr_geo->blksize) +
			value_size + XATTR_NAME_MAX + 1;

	/*
	 * If there's already a buffer, figure out if we need to reallocate it
	 * to accommodate a larger size.
	 */
	if (ab && ab->sz >= sz)
		return 0;

	/* Give back the old memory as soon as we can, to reduce pressure. */
	if (!preserve && ab) {
		kmem_free(ab);
		ab = NULL;
	}

	new_ab = kmem_alloc_large(sizeof(*new_ab) + sz, KM_MAYFAIL);
	if (!new_ab)
		return -ENOMEM;

	if (ab) {
		memcpy(new_ab, ab, ab->sz);
		kmem_free(ab);
	}
	new_ab->sz = sz;
	sc->buf = new_ab;
	return 0;
}

/*
 * While we're salvaging the contents of an xattr block, the first part of the
 * buffer contains a bitmap of the parts of the block that we've already seen.
 * Therefore, salvaged values /must/ be stored after the bitmap.
 */
static inline unsigned char *
xrep_xattr_salvage_valuebuf(
	struct xfs_scrub	*sc)
{
	return (unsigned char *)(xchk_xattr_usedmap(sc) +
				 BITS_TO_LONGS(sc->mp->m_attr_geo->blksize));
}

/*
 * Decide if we want to salvage this attribute.  We don't bother with
 * incomplete or oversized keys or values.
 */
STATIC int
xrep_xattr_want_salvage(
	int			flags,
	const void		*name,
	int			namelen,
	int			valuelen)
{
	if (flags & XFS_ATTR_INCOMPLETE)
		return false;
	if (namelen > XATTR_NAME_MAX || namelen <= 0)
		return false;
	if (valuelen > XATTR_SIZE_MAX || valuelen < 0)
		return false;
	if (!xfs_attr_namecheck(name, namelen))
		return false;
	return true;
}

/* Allocate an in-core record to hold xattrs while we rebuild the xattr data. */
STATIC int
xrep_xattr_salvage_key(
	struct xrep_xattr	*rx,
	int			flags,
	unsigned char		*name,
	int			namelen,
	unsigned char		*value,
	int			valuelen)
{
	struct xrep_xattr_key	key = {
		.valuelen	= valuelen,
		.flags		= flags & (XFS_ATTR_ROOT | XFS_ATTR_SECURE),
		.namelen	= namelen,
	};
	int			error = 0;

	if (xchk_should_terminate(rx->sc, &error))
		return error;

	trace_xrep_xattr_salvage_key(rx->sc->ip, key.flags, name, namelen,
			valuelen);

	error = xblob_put(rx->xattr_blobs, &key.name_cookie, name, namelen);
	if (error)
		return error;
	error = xblob_put(rx->xattr_blobs, &key.value_cookie, value, valuelen);
	if (error)
		return error;

	key.hash = xfs_da_hashname(name, namelen);

	error = xfbma_append(rx->xattr_records, &key);
	if (error)
		return error;

	rx->attrs_found++;
	return 0;
}

/*
 * Record a shortform extended attribute key & value for later reinsertion
 * into the inode.
 */
STATIC int
xrep_xattr_salvage_sf_attr(
	struct xrep_xattr		*rx,
	struct xfs_attr_sf_entry	*sfe)
{
	unsigned char			*value = &sfe->nameval[sfe->namelen];

	if (!xrep_xattr_want_salvage(sfe->flags, sfe->nameval, sfe->namelen,
			sfe->valuelen))
		return 0;

	return xrep_xattr_salvage_key(rx, sfe->flags, sfe->nameval,
			sfe->namelen, value, sfe->valuelen);
}

/*
 * Record a local format extended attribute key & value for later reinsertion
 * into the inode.
 */
STATIC int
xrep_xattr_salvage_local_attr(
	struct xrep_xattr		*rx,
	struct xfs_attr_leaf_entry	*ent,
	unsigned int			nameidx,
	const char			*buf_end,
	struct xfs_attr_leaf_name_local	*lentry)
{
	unsigned char			*value;
	unsigned long			*usedmap = xchk_xattr_usedmap(rx->sc);
	unsigned int			valuelen;
	unsigned int			namesize;

	/*
	 * Decode the leaf local entry format.  If something seems wrong, we
	 * junk the attribute.
	 */
	valuelen = be16_to_cpu(lentry->valuelen);
	namesize = xfs_attr_leaf_entsize_local(lentry->namelen, valuelen);
	if ((char *)lentry + namesize > buf_end)
		return 0;
	if (!xrep_xattr_want_salvage(ent->flags, lentry->nameval,
			lentry->namelen, valuelen))
		return 0;
	if (!xchk_xattr_set_map(rx->sc, usedmap, nameidx, namesize))
		return 0;

	/* Try to save this attribute. */
	value = &lentry->nameval[lentry->namelen];
	return xrep_xattr_salvage_key(rx, ent->flags, lentry->nameval,
			lentry->namelen, value, valuelen);
}

/*
 * Record a remote format extended attribute key & value for later reinsertion
 * into the inode.
 */
STATIC int
xrep_xattr_salvage_remote_attr(
	struct xrep_xattr		*rx,
	struct xfs_attr_leaf_entry	*ent,
	unsigned int			nameidx,
	const char			*buf_end,
	struct xfs_attr_leaf_name_remote *rentry,
	unsigned int			ent_idx,
	struct xfs_buf			*leaf_bp)
{
	struct xfs_da_args		args = {
		.trans	= rx->sc->tp,
		.dp	= rx->sc->ip,
		.index	= ent_idx,
		.geo	= rx->sc->mp->m_attr_geo,
	};
	unsigned long			*usedmap = xchk_xattr_usedmap(rx->sc);
	unsigned char			*value;
	unsigned int			valuelen;
	unsigned int			namesize;
	int				error;

	/*
	 * Decode the leaf remote entry format.  If something seems wrong, we
	 * junk the attribute.  Note that we should never find a zero-length
	 * remote attribute value.
	 */
	valuelen = be32_to_cpu(rentry->valuelen);
	namesize = xfs_attr_leaf_entsize_remote(rentry->namelen);
	if ((char *)rentry + namesize > buf_end)
		return 0;
	if (valuelen == 0 ||
	    !xrep_xattr_want_salvage(ent->flags, rentry->name, rentry->namelen,
			valuelen))
		return 0;
	if (!xchk_xattr_set_map(rx->sc, usedmap, nameidx, namesize))
		return 0;

	/*
	 * Enlarge the buffer (if needed) to hold the value that we're trying
	 * to salvage from the old extended attribute data.  The usedmap
	 * pointer itself may be invalid after this point, but we must keep the
	 * bitmap.
	 */
	error = xrep_setup_xattr_buf(rx->sc, valuelen, true);
	if (error == -ENOMEM)
		error = -EDEADLOCK;
	if (error)
		return error;
	value = xrep_xattr_salvage_valuebuf(rx->sc);

	/* Look up the remote value and stash it for reconstruction. */
	args.valuelen = valuelen;
	args.namelen = rentry->namelen;
	args.name = rentry->name;
	args.value = value;
	error = xfs_attr3_leaf_getvalue(leaf_bp, &args);
	if (error || args.rmtblkno == 0)
		goto err_free;

	error = xfs_attr_rmtval_get(&args);
	if (error)
		goto err_free;

	/* Try to save this attribute. */
	error = xrep_xattr_salvage_key(rx, ent->flags, rentry->name,
			rentry->namelen, value, valuelen);
err_free:
	/* remote value was garbage, junk it */
	if (error == -EFSBADCRC || error == -EFSCORRUPTED)
		error = 0;
	return error;
}

/* Extract every xattr key that we can from this attr fork block. */
STATIC int
xrep_xattr_recover_leaf(
	struct xrep_xattr		*rx,
	struct xfs_buf			*bp)
{
	struct xfs_attr3_icleaf_hdr	leafhdr;
	struct xfs_scrub		*sc = rx->sc;
	struct xfs_mount		*mp = sc->mp;
	struct xfs_attr_leafblock	*leaf;
	unsigned long			*usedmap = xchk_xattr_usedmap(sc);
	struct xfs_attr_leaf_name_local	*lentry;
	struct xfs_attr_leaf_name_remote *rentry;
	struct xfs_attr_leaf_entry	*ent;
	struct xfs_attr_leaf_entry	*entries;
	char				*buf_end;
	size_t				off;
	unsigned int			nameidx;
	unsigned int			hdrsize;
	int				i;
	int				error = 0;

	bitmap_zero(usedmap, mp->m_attr_geo->blksize);

	/* Check the leaf header */
	leaf = bp->b_addr;
	xfs_attr3_leaf_hdr_from_disk(mp->m_attr_geo, &leafhdr, leaf);
	hdrsize = xfs_attr3_leaf_hdr_size(leaf);
	xchk_xattr_set_map(sc, usedmap, 0, hdrsize);
	entries = xfs_attr3_leaf_entryp(leaf);

	buf_end = (char *)bp->b_addr + mp->m_attr_geo->blksize;
	for (i = 0, ent = entries; i < leafhdr.count; ent++, i++) {
		if (xchk_should_terminate(sc, &error))
			break;

		/* Skip key if it conflicts with something else? */
		off = (char *)ent - (char *)leaf;
		if (!xchk_xattr_set_map(sc, usedmap, off,
				sizeof(xfs_attr_leaf_entry_t)))
			continue;

		/* Check the name information. */
		nameidx = be16_to_cpu(ent->nameidx);
		if (nameidx < leafhdr.firstused ||
		    nameidx >= mp->m_attr_geo->blksize)
			continue;

		if (ent->flags & XFS_ATTR_LOCAL) {
			lentry = xfs_attr3_leaf_name_local(leaf, i);
			error = xrep_xattr_salvage_local_attr(rx, ent, nameidx,
					buf_end, lentry);
		} else {
			rentry = xfs_attr3_leaf_name_remote(leaf, i);
			error = xrep_xattr_salvage_remote_attr(rx, ent, nameidx,
					buf_end, rentry, i, bp);
		}
		if (error)
			break;
	}

	return error;
}

/* Try to recover shortform attrs. */
STATIC int
xrep_xattr_recover_sf(
	struct xrep_xattr		*rx)
{
	struct xfs_attr_shortform	*sf;
	struct xfs_attr_sf_entry	*sfe;
	struct xfs_attr_sf_entry	*next;
	struct xfs_ifork		*ifp;
	unsigned char			*end;
	int				i;
	int				error;

	ifp = XFS_IFORK_PTR(rx->sc->ip, XFS_ATTR_FORK);
	sf = (struct xfs_attr_shortform *)rx->sc->ip->i_afp->if_u1.if_data;
	end = (unsigned char *)ifp->if_u1.if_data + ifp->if_bytes;

	for (i = 0, sfe = &sf->list[0]; i < sf->hdr.count; i++) {
		if (xchk_should_terminate(rx->sc, &error))
			break;

		next = xfs_attr_sf_nextentry(sfe);
		if ((unsigned char *)next > end)
			break;

		/* Ok, let's save this key/value. */
		error = xrep_xattr_salvage_sf_attr(rx, sfe);
		if (error)
			return error;

		sfe = next;
	}

	return 0;
}

/*
 * Try to return a buffer of xattr data for a given physical extent.
 *
 * Because the buffer cache get function complains if it finds a buffer
 * matching the block number but not matching the length, we must be careful to
 * look for incore buffers (up to the maximum length of a remote value) that
 * could be hiding anywhere in the physical range.  If we find an incore
 * buffer, we can pass that to the caller.  Optionally, read a single block and
 * pass that back.
 *
 * Note the subtlety that remote attr value blocks for which there is no incore
 * buffer will be passed to the callback one block at a time.  These buffers
 * will not have any ops attached and must be staled to prevent aliasing with
 * multiblock buffers once we drop the ILOCK.
 */
STATIC int
xrep_xattr_find_buf(
	struct xfs_mount	*mp,
	xfs_fsblock_t		fsbno,
	xfs_filblks_t		max_len,
	bool			can_read,
	struct xfs_buf		**bpp)
{
	xfs_daddr_t		daddr = XFS_FSB_TO_DADDR(mp, fsbno);

	max_len = min_t(xfs_filblks_t, max_len,
				xfs_attr3_rmt_blocks(mp, XFS_XATTR_SIZE_MAX));

	/*
	 * Look for an incore buffer for every possible rmt or leaf block that
	 * could start at this physical position.
	 */
	while (max_len > 0) {
		struct xfs_buf	*bp = xfs_buf_incore(mp->m_ddev_targp, daddr,
				XFS_FSB_TO_BB(mp, max_len),
				XBF_TRYLOCK | XBF_SCAN_STALE);
		if (bp) {
			*bpp = bp;
			return 0;
		}

		max_len--;
	}

	if (!can_read) {
		*bpp = NULL;
		return 0;
	}

	return xfs_buf_read(mp->m_ddev_targp, daddr, XFS_FSB_TO_BB(mp, 1),
			XBF_TRYLOCK, bpp, NULL);
}

/*
 * Deal with a buffer that we found during our walk of the attr fork.
 *
 * Attribute leaf and node blocks are simple -- they're a single block, so we
 * can walk them one at a time and we never have to worry about discontiguous
 * multiblock buffers like we do for directories.
 *
 * Unfortunately, remote attr blocks add a lot of complexity here.  Each disk
 * block is totally self contained, in the sense that the v5 header provides no
 * indication that there could be more data in the next block.  The incore
 * buffers can span multiple blocks, though they never cross extent records.
 * However, they don't necessarily start or end on an extent record boundary.
 * Therefore, we need a special buffer find function to walk the buffer cache
 * for us.
 *
 * The caller must hold the ILOCK on the file being repaired.  We use
 * XBF_TRYLOCK here to skip any locked buffer on the assumption that we don't
 * own the block and don't want to hang the system on a potentially garbage
 * buffer.
 */
STATIC int
xrep_xattr_recover_block(
	struct xrep_xattr	*rx,
	xfs_dablk_t		dabno,
	xfs_fsblock_t		fsbno,
	xfs_filblks_t		max_len,
	xfs_filblks_t		*actual_len)
{
	struct xfs_da_blkinfo	*info;
	struct xfs_buf		*bp;
	int			error;

	error = xrep_xattr_find_buf(rx->sc->mp, fsbno, max_len, true, &bp);
	if (error)
		return error;
	info = bp->b_addr;
	*actual_len = XFS_BB_TO_FSB(rx->sc->mp, bp->b_length);

	trace_xrep_xattr_recover_leafblock(rx->sc->ip, dabno,
			be16_to_cpu(info->magic));

	/*
	 * If the buffer has the right magic number for an attr leaf block and
	 * passes a structure check (we don't care about checksums), salvage
	 * as much as we can from the block. */
	if (info->magic == cpu_to_be16(XFS_ATTR3_LEAF_MAGIC) &&
	    xrep_buf_verify_struct(bp, &xfs_attr3_leaf_buf_ops))
		error = xrep_xattr_recover_leaf(rx, bp);

	/*
	 * If the buffer didn't already have buffer ops set, it was read in by
	 * the _find_buf function and could very well be /part/ of a multiblock
	 * remote block.  Mark it stale so that it doesn't hang around in
	 * memory to cause problems.
	 */
	if (bp->b_ops == NULL)
		xfs_buf_stale(bp);

	xfs_buf_relse(bp);
	return error;
}

/* Insert one xattr key/value. */
STATIC int
xrep_xattr_insert_rec(
	struct xrep_xattr		*rx,
	const struct xrep_xattr_key	*key)
{
	struct xfs_da_args		args = { NULL };
	unsigned char			*name;
	unsigned char			*value;
	int				error;

	/*
	 * We want to use a separate transaction for each attribute that we're
	 * adding to the temporary file.  However, xattr salvaging uses the
	 * scrub transaction to avoid livelocking on attr tree loops, so we
	 * have to commit the existing scrub transaction to get it out of the
	 * way.
	 */
	error = xfs_trans_commit(rx->sc->tp);
	if (error)
		return error;
	rx->sc->tp = NULL;

	/*
	 * Grab pointers to the scrub buffer so that we can use them to insert
	 * attrs into the temp file.  Because the salvage step should have made
	 * the buffer large enough for (a block bitmap + the largest value
	 * found + the largest possible attr name), it should be safe to use
	 * xfs_xattr_usedmap to copy values.
	 */
	name = xchk_xattr_namebuf(rx->sc);
	value = (unsigned char *)xchk_xattr_usedmap(rx->sc);

	/*
	 * The attribute name is stored near the end of the in-core buffer,
	 * though we reserve one more byte to ensure null termination.
	 */
	name[XATTR_NAME_MAX] = 0;

	error = xblob_get(rx->xattr_blobs, key->name_cookie, name,
			key->namelen);
	if (error)
		return error;

	error = xblob_free(rx->xattr_blobs, key->name_cookie);
	if (error)
		return error;

	error = xblob_get(rx->xattr_blobs, key->value_cookie, value,
			key->valuelen);
	if (error)
		return error;

	error = xblob_free(rx->xattr_blobs, key->value_cookie);
	if (error)
		return error;

	name[key->namelen] = 0;

	trace_xrep_xattr_insert_rec(rx->sc->tempip, key->flags, name,
			key->namelen, key->valuelen);

	/*
	 * Drop everything so that we can add the attribute to the tempfile.
	 * The attr set code is very intricate and can roll the transaction
	 * multiple times.  We have no way to make it relog both the tempfile
	 * and the file we're repairing, so we're willing to do this to avoid
	 * having to know too much about the details.  We still hold the
	 * IOLOCK on the file being repaired, so we can prevent userspace from
	 * adding more attrs to the file we're repairing.
	 */
	xfs_iunlock(rx->sc->ip, XFS_ILOCK_EXCL);
	xfs_iunlock(rx->sc->tempip, XFS_ILOCK_EXCL);
	rx->sc->ilock_flags &= ~XFS_ILOCK_EXCL;
	rx->sc->temp_ilock_flags &= ~XFS_ILOCK_EXCL;

	args.dp = rx->sc->tempip;
	args.attr_filter = key->flags;
	args.name = name;
	args.namelen = key->namelen;
	args.value = value;
	args.valuelen = key->valuelen;
	error = xfs_attr_set(&args);
	if (error)
		return error;

	/* Now recreate the transaction and relock the inodes. */
	error = xchk_trans_alloc(rx->sc, 0);
	if (error)
		return error;

	xfs_lock_two_inodes(rx->sc->ip, XFS_ILOCK_EXCL, rx->sc->tempip,
			XFS_ILOCK_EXCL);
	rx->sc->ilock_flags |= XFS_ILOCK_EXCL;
	rx->sc->temp_ilock_flags |= XFS_ILOCK_EXCL;
	return 0;
}

/*
 * Periodically flush salvaged attributes to the temporary file.  This
 * is done to reduce the memory requirements of the xattr rebuild, since
 * directories can contain millions of attributes.
 */
STATIC int
xrep_xattr_flush_salvaged(
	struct xrep_xattr	*rx)
{
	struct xrep_xattr_key	key;
	uint64_t		nr;
	int			error;

	/* Add all the salvaged attrs to the temporary file. */
	for (nr = 0; nr < xfbma_length(rx->xattr_records);) {
		error = xfbma_iter_get(rx->xattr_records, &nr, &key);
		if (error)
			return error;
		error = xrep_xattr_insert_rec(rx, &key);
		if (error)
			return error;
	}

	/* Empty out both arrays now that we've added the entries. */
	xfbma_truncate(rx->xattr_records);
	xblob_truncate(rx->xattr_blobs);
	return 0;
}

/* Extract as many attribute keys and values as we can. */
STATIC int
xrep_xattr_recover(
	struct xrep_xattr	*rx)
{
	struct xfs_bmbt_irec	got;
	struct xfs_scrub	*sc = rx->sc;
	struct xfs_da_geometry	*geo = sc->mp->m_attr_geo;
	xfs_fileoff_t		offset;
	xfs_filblks_t		len;
	xfs_dablk_t		dabno;
	int			nmap;
	int			error;

	/*
	 * Iterate each xattr leaf block in the attr fork to scan them for any
	 * attributes that we might salvage.
	 */
	for (offset = 0;
	     offset < XFS_MAX_FILEOFF;
	     offset = got.br_startoff + got.br_blockcount) {
		nmap = 1;
		error = xfs_bmapi_read(sc->ip, offset, XFS_MAX_FILEOFF - offset,
				&got, &nmap, XFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		if (nmap != 1)
			return -EFSCORRUPTED;
		if (!xfs_bmap_is_written_extent(&got))
			continue;

		for (dabno = round_up(got.br_startoff, geo->fsbcount);
		     dabno < got.br_startoff + got.br_blockcount;
		     dabno += len) {
			xfs_fileoff_t	curr_offset = dabno - got.br_startoff;

			if (xchk_should_terminate(rx->sc, &error))
				return error;

			error = xrep_xattr_recover_block(rx, dabno,
					curr_offset + got.br_startblock,
					got.br_blockcount - curr_offset,
					&len);
			if (error)
				return error;

			/* Flush attrs to constrain memory usage. */
			if (xfbma_bytes(rx->xattr_records) +
			    xblob_bytes(rx->xattr_blobs) <
			    XREP_XATTR_SALVAGE_BYTES)
				continue;

			error = xrep_xattr_flush_salvaged(rx);
			if (error)
				return error;
		}
	}

	return 0;
}

/*
 * Reset the extended attribute fork to a state where we can start re-adding
 * the salvaged attributes.
 */
STATIC int
xrep_xattr_fork_remove(
	struct xfs_scrub	*sc,
	struct xfs_inode	*ip)
{
	struct xfs_attr_sf_hdr	*hdr;
	struct xfs_ifork	*ifp = XFS_IFORK_PTR(ip, XFS_ATTR_FORK);

	/*
	 * If the data fork is in btree format, we can't change di_forkoff
	 * because we could run afoul of the rule that the data fork isn't
	 * supposed to be in btree format if there's enough space in the fork
	 * that it could have used extents format.  Instead, reinitialize the
	 * attr fork to have a shortform structure with zero attributes.
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE) {
		ifp->if_format = XFS_DINODE_FMT_LOCAL;
		xfs_idata_realloc(ip, (int)sizeof(*hdr) - ifp->if_bytes,
				XFS_ATTR_FORK);
		hdr = (struct xfs_attr_sf_hdr *)ifp->if_u1.if_data;
		hdr->count = 0;
		hdr->totsize = cpu_to_be16(sizeof(*hdr));
		xfs_trans_log_inode(sc->tp, ip,
				XFS_ILOG_CORE | XFS_ILOG_ADATA);
		return 0;
	}

	/* If we still have attr fork extents, something's wrong. */
	if (ifp->if_nextents != 0) {
		struct xfs_iext_cursor	icur;
		struct xfs_bmbt_irec	irec;
		unsigned int		i = 0;

		xfs_emerg(sc->mp,
	"inode 0x%llx attr fork still has %u attr extents, format %d?!",
				ip->i_ino, ifp->if_nextents, ifp->if_format);
		for_each_xfs_iext(ifp, &icur, &irec) {
			xfs_err(sc->mp, "[%u]: startoff %llu startblock %llu blockcount %llu state %u", i++, irec.br_startoff, irec.br_startblock, irec.br_blockcount, irec.br_state);
		}
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	xfs_attr_fork_remove(ip, sc->tp);
	return 0;
}

/*
 * Free all the attribute fork blocks and delete the fork.  The caller must
 * join the inode to the transaction.  This function returns with the inode
 * joined to a clean scrub transaction.
 */
int
xrep_xattr_reset_fork(
	struct xfs_scrub	*sc,
	struct xfs_inode	*ip)
{
	struct xfs_bmbt_irec	got;
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_da_geometry	*geo = sc->mp->m_attr_geo;
	struct xfs_buf		*bp;
	xfs_fileoff_t		offset = 0;
	xfs_filblks_t		len;
	xfs_dablk_t		dabno;
	int			nmap;
	int			error;

	ASSERT(ip == sc->ip || ip == sc->tempip);

	if (ip->i_afp->if_format == XFS_DINODE_FMT_LOCAL)
		goto zap;

	/* Invalidate each attr block in the attr fork.  Do not do reads. */
	for (offset = 0;
	     offset < XFS_MAX_FILEOFF;
	     offset = got.br_startoff + got.br_blockcount) {
		/* Walk the attr fork piece by piece... */
		nmap = 1;
		error = xfs_bmapi_read(ip, offset, XFS_MAX_FILEOFF - offset,
				&got, &nmap, XFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		if (nmap != 1)
			return -EFSCORRUPTED;
		if (!xfs_bmap_is_real_extent(&got))
			continue;

		for (dabno = round_up(got.br_startoff, geo->fsbcount);
		     dabno < got.br_startoff + got.br_blockcount;
		     dabno += len) {
			xfs_fileoff_t	curr_offset = dabno - got.br_startoff;

			error = xrep_xattr_find_buf(mp,
					curr_offset + got.br_startblock,
					got.br_blockcount - curr_offset,
					false, &bp);
			if (error)
				break;
			if (!bp) {
				/* No buffer found?  Advance by one block. */
				len = geo->fsbcount;
				continue;
			}
			len = XFS_BB_TO_FSB(mp, bp->b_length);

			xfs_buf_stale(bp);
			xfs_buf_relse(bp);
		}
	}

	/* Free all the old xattr blocks; don't discard them for speed. */
	error = xfs_bunmapi_range(&sc->tp, ip,
			XFS_BMAPI_NODISCARD | XFS_BMAPI_ATTRFORK,
			0, XFS_MAX_FILEOFF);
	if (error)
		return error;

zap:
	error = xrep_xattr_fork_remove(sc, ip);
	if (error)
		return error;

	return xrep_roll_trans(sc);
}

/*
 * Find all the extended attributes for this inode by scraping them out of the
 * attribute key blocks by hand, and flushing them into the temp file.
 */
STATIC int
xrep_xattr_find_attributes(
	struct xrep_xattr	*rx)
{
	struct xfs_inode	*ip = rx->sc->ip;
	int			error;

	error = xrep_ino_dqattach(rx->sc);
	if (error)
		return error;

	/* Salvage attributes from the old file. */
	if (rx->sc->ip->i_afp->if_format == XFS_DINODE_FMT_LOCAL) {
		error = xrep_xattr_recover_sf(rx);
	} else {
		error = xfs_iread_extents(rx->sc->tp, ip, XFS_ATTR_FORK);
		if (error)
			return error;

		error = xrep_xattr_recover(rx);
	}
	if (error)
		return error;

	return xrep_xattr_flush_salvaged(rx);
}

/*
 * Prepare both inodes' attribute forks for extent swapping.  Promote the
 * tempfile from short format to leaf format, and if the file being repaired
 * has a short format attr fork, turn it into an empty extent list.
 */
STATIC int
xrep_xattr_swap_prep(
	struct xfs_scrub	*sc,
	bool			temp_local,
	bool			ip_local)
{
	int			error;

	/*
	 * If the tempfile's attributes are in shortform format, convert that
	 * to a single leaf extent so that we can use the atomic extent swap.
	 */
	if (temp_local) {
		struct xfs_buf		*leaf_bp = NULL;
		struct xfs_da_args	args = {
			.dp		= sc->tempip,
			.geo		= sc->mp->m_attr_geo,
			.whichfork	= XFS_ATTR_FORK,
			.trans		= sc->tp,
			.total		= 1,
		};

		error = xfs_attr_shortform_to_leaf(&args, &leaf_bp);
		if (error)
			return error;

		/*
		 * Roll the deferred log items to get us back to a clean
		 * transaction.  Hold on to the leaf buffer across this roll
		 * so that the AIL cannot grab our half-baked block.
		 */
		xfs_trans_bhold(sc->tp, leaf_bp);
		error = xfs_defer_finish(&sc->tp);
		xfs_trans_bhold_release(sc->tp, leaf_bp);
	}

	/*
	 * If the file being repaired had a shortform attribute fork, convert
	 * that to an empty extent list in preparation for the atomic extent
	 * swap.
	 */
	if (ip_local) {
		struct xfs_ifork	*ifp;

		ifp = XFS_IFORK_PTR(sc->ip, XFS_ATTR_FORK);

		xfs_idestroy_fork(ifp);
		ifp->if_format = XFS_DINODE_FMT_EXTENTS;
		ifp->if_nextents = 0;
		ifp->if_bytes = 0;
		ifp->if_u1.if_root = NULL;
		ifp->if_height = 0;

		xfs_trans_log_inode(sc->tp, sc->ip,
				XFS_ILOG_CORE | XFS_ILOG_ADATA);
	}

	return 0;
}

/* State we need to track while rewriting attr block owners. */
struct xrep_xattr_swap_owner {
	struct xfs_attr_list_context	ctx;
	struct xbitmap			rmt_blocks;
	struct xfs_scrub		*sc;
};

/*
 * Change the owner field of a remote attribute value block to match the file
 * that's being repaired.  In-core buffers for these values span a single
 * extent and are never logged, so we must be careful to mask off the
 * corresponding range so that the leaf/node pass will skip these parts of the
 * attr fork mappings.
 */
static void
xrep_xattr_swap_rmt_owner(
	struct xfs_attr_list_context	*context,
	int				flags,
	unsigned char			*name,
	int				namelen,
	int				valuelen)
{
	struct xfs_da_args		args = {
		.op_flags		= XFS_DA_OP_NOTIME,
		.attr_filter		= flags & XFS_ATTR_NSP_ONDISK_MASK,
		.geo			= context->dp->i_mount->m_attr_geo,
		.whichfork		= XFS_ATTR_FORK,
		.dp			= context->dp,
		.name			= name,
		.namelen		= namelen,
		.hashval		= xfs_da_hashname(name, namelen),
		.trans			= context->tp,
		.value			= NULL,
		.valuelen		= 0,
	};
	LIST_HEAD(buffer_list);
	struct xfs_bmbt_irec		map;
	struct xrep_xattr_swap_owner	*xso;
	struct xfs_mount		*mp = context->dp->i_mount;
	struct xfs_attr3_rmt_hdr	*rmt;
	struct xfs_buf			*bp;
	void				*p;
	xfs_daddr_t			dblkno;
	int				dblkcnt;
	int				nmap;
	int				error;

	xso = container_of(context, struct xrep_xattr_swap_owner, ctx);

	if (flags & (XFS_ATTR_LOCAL | XFS_ATTR_INCOMPLETE))
		return;

	error = xfs_attr_get_ilocked(&args);
	if (error)
		goto fail;

	/*
	 * Mark this region of the attr fork so that the leaf/node scan will
	 * skip this part.
	 */
	error = xbitmap_set(&xso->rmt_blocks, args.rmtblkno, args.rmtblkcnt);
	if (error)
		goto fail;

	while (args.rmtblkcnt > 0) {
		nmap = 1;
		error = xfs_bmapi_read(args.dp, args.rmtblkno, args.rmtblkcnt,
				&map, &nmap, XFS_BMAPI_ATTRFORK);
		if (error || nmap != 1)
			goto fail;

		if (!xfs_bmap_is_written_extent(&map))
			goto fail;

		dblkno = XFS_FSB_TO_DADDR(mp, map.br_startblock);
		dblkcnt = XFS_FSB_TO_BB(mp, map.br_blockcount);
		error = xfs_buf_read(mp->m_ddev_targp, dblkno, dblkcnt, 0, &bp,
				&xfs_attr3_rmt_buf_ops);
		if (error)
			goto fail;

		/*
		 * Each rmt block within the buffer gets its own header, so
		 * update the owner for each header.
		 */
		for (p = bp->b_addr;
		     p < bp->b_addr + BBTOB(bp->b_length);
		     p += mp->m_attr_geo->blksize) {
			rmt = p;
			rmt->rm_owner = cpu_to_be64(xso->sc->ip->i_ino);
		}

		xfs_buf_delwri_queue(bp, &buffer_list);
		xfs_buf_relse(bp);

		/* roll attribute extent map forwards */
		args.rmtblkno += map.br_blockcount;
		args.rmtblkcnt -= map.br_blockcount;
	}

	/* Write the entire remote value to disk. */
	error = xfs_buf_delwri_submit(&buffer_list);
	if (error)
		goto fail;

	return;
fail:
	xfs_buf_delwri_cancel(&buffer_list);
	context->seen_enough = 1;
}

/*
 * Change the owner field of every block in the attribute fork to match the
 * file being repaired.  First we fix the remote value blocks (which have
 * particular incore geometries) and then change the rest one block at a time.
 */
STATIC int
xrep_xattr_swap_leaf_owner(
	struct xrep_xattr_swap_owner	*xso)
{
	struct xfs_bmbt_irec		map;
	struct xfs_da_geometry		*geo = xso->sc->mp->m_attr_geo;
	struct xfs_scrub		*sc = xso->sc;
	struct xfs_da3_blkinfo		*info;
	struct xfs_buf			*bp;
	xfs_fileoff_t			offset = 0;
	xfs_fileoff_t			end = -1U;
	xfs_dablk_t			dabno;
	int				nmap;
	int				error;

	for (offset = 0;
	     offset < end;
	     offset = map.br_startoff + map.br_blockcount) {
		nmap = 1;
		error = xfs_bmapi_read(sc->tempip, offset, end - offset,
				&map, &nmap, XFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		if (nmap != 1)
			return -EFSCORRUPTED;
		if (!xfs_bmap_is_written_extent(&map)) {
			continue;
		}

		if (xbitmap_test(&xso->rmt_blocks, map.br_startoff,
				 &map.br_blockcount)) {
			continue;
		}

		for (dabno = round_up(map.br_startoff, geo->fsbcount);
		     dabno < map.br_startoff + map.br_blockcount;
		     dabno += geo->fsbcount) {
			error = xfs_da_read_buf(sc->tp, sc->tempip,
					dabno, 0, &bp, XFS_ATTR_FORK, NULL);
			if (error)
				return error;
			if (!bp)
				return -EFSCORRUPTED;

			info = bp->b_addr;
			info->owner = cpu_to_be64(sc->ip->i_ino);

			/* If nobody set a buffer type or ops, set them now. */
			if (bp->b_ops == NULL) {
				switch (info->hdr.magic) {
				case cpu_to_be16(XFS_ATTR3_LEAF_MAGIC):
					bp->b_ops = &xfs_attr3_leaf_buf_ops;
					break;
				case cpu_to_be16(XFS_DA3_NODE_MAGIC):
					bp->b_ops = &xfs_da3_node_buf_ops;
					break;
				default:
					xfs_trans_brelse(sc->tp, bp);
					return -EFSCORRUPTED;
				}
				xfs_buf_set_ref(bp, XFS_ATTR_BTREE_REF);
			}

			xfs_trans_ordered_buf(sc->tp, bp);
			xfs_trans_brelse(sc->tp, bp);
		}
	}

	return 0;
}
/*
 * Walk the temporary file's xattr blocks, setting the owner field of each
 * block to the new owner.  We use ordered and delwri buffers to flush
 * everything out to disk ahead of comitting the atomic extent swap.  Rewriting
 * the attr blocks like this is apparently safe because attr inactivation isn't
 * picky about owner field enforcement(!)
 */
STATIC int
xrep_xattr_swap_owner(
	struct xfs_scrub		*sc)
{
	struct xrep_xattr_swap_owner	xso = {
		.ctx.dp			= sc->tempip,
		.ctx.resynch		= 1,
		.ctx.put_listent	= xrep_xattr_swap_rmt_owner,
		.ctx.allow_incomplete	= false,
		.ctx.seen_enough	= 0,
		.ctx.tp			= sc->tp,
		.sc			= sc,
	};
	int				error;

	xbitmap_init(&xso.rmt_blocks);

	/* First pass -- change the owners of the remote blocks. */
	error = xfs_attr_list_ilocked(&xso.ctx);
	if (error)
		goto out;
	if (xso.ctx.seen_enough) {
		error = -EFSCORRUPTED;
		goto out;
	}

	/* Second pass -- change each attr leaf/node buffer. */
	error = xrep_xattr_swap_leaf_owner(&xso);
out:
	xbitmap_destroy(&xso.rmt_blocks);
	return error;
}

/*
 * If both files' attribute structure are in short format, we can copy
 * the short format data from the tempfile to the repaired file if it'll
 * fit.
 */
STATIC void
xrep_xattr_swap_local(
	struct xfs_scrub	*sc,
	int			newsize,
	int			forkoff)
{
	struct xfs_ifork	*ifp1, *ifp2;

	ifp1 = XFS_IFORK_PTR(sc->tempip, XFS_ATTR_FORK);
	ifp2 = XFS_IFORK_PTR(sc->ip, XFS_ATTR_FORK);
	sc->ip->i_forkoff = forkoff;

	xfs_idata_realloc(sc->ip, ifp1->if_bytes - ifp2->if_bytes,
			XFS_ATTR_FORK);

	memcpy(ifp2->if_u1.if_data, ifp1->if_u1.if_data, newsize);
	xfs_trans_log_inode(sc->tp, sc->ip, XFS_ILOG_CORE | XFS_ILOG_ADATA);
}

/* Swap the temporary file's attribute fork with the one being repaired. */
STATIC int
xrep_xattr_swap(
	struct xrep_xattr	*rx)
{
	struct xfs_swapext_req	req;
	struct xfs_swapext_res	res;
	struct xfs_scrub	*sc = rx->sc;
	bool			ip_local, temp_local;
	int			error;

	error = xrep_swapext_prep(rx->sc, XFS_ATTR_FORK, &req, &res);
	if (error)
		return error;

	error = xchk_trans_alloc(sc, res.resblks);
	if (error)
		return error;

	sc->temp_ilock_flags |= XFS_ILOCK_EXCL;
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	xfs_xchg_range_ilock(sc->tp, sc->ip, sc->tempip);

	ip_local = sc->ip->i_afp->if_format == XFS_DINODE_FMT_LOCAL;
	temp_local = sc->tempip->i_afp->if_format == XFS_DINODE_FMT_LOCAL;

	/*
	 * If the both files have a local format attr fork and the rebuilt
	 * xattr data would fit in the repaired file's attr fork, just copy
	 * the contents from the tempfile and declare ourselves done.
	 */
	if (ip_local && temp_local) {
		int	forkoff;
		int	newsize;

		newsize = xfs_attr_sf_totsize(sc->tempip);
		forkoff = xfs_attr_shortform_bytesfit(sc->ip, newsize);
		if (forkoff > 0) {
			xrep_xattr_swap_local(sc, newsize, forkoff);
			return 0;
		}
	}

	/* Otherwise, make sure both attr forks are in block-mapping mode. */
	error = xrep_xattr_swap_prep(sc, temp_local, ip_local);
	if (error)
		return error;

	/* Rewrite the owner field of all attr blocks in the temporary file. */
	error = xrep_xattr_swap_owner(sc);
	if (error)
		return error;

	return xfs_swapext(&sc->tp, &req);
}

/*
 * Insert into the tempfile all the attributes that we collected.
 *
 * Commit the repair transaction and drop the ilock because the attribute
 * setting code needs to be able to allocate special transactions and take the
 * ilock on its own.  The attributes are added to the temporary file (which can
 * be disposed of easily on failure).  If we finish rebuilding all of the
 * salvageable attrs, we can then use atomic extent swapping to commit the
 * new attr index to the file.
 */
STATIC int
xrep_xattr_rebuild_tree(
	struct xrep_xattr	*rx)
{
	int			error;

	/*
	 * If we didn't find any attributes to salvage, repair the file by
	 * zapping the attr fork.  Join the temp file so that we keep it
	 * rolling forward along with the file being repaired.
	 */
	if (rx->attrs_found == 0) {
		xfs_trans_ijoin(rx->sc->tp, rx->sc->tempip, 0);
		xfs_trans_ijoin(rx->sc->tp, rx->sc->ip, 0);
		return xrep_xattr_reset_fork(rx->sc, rx->sc->ip);
	}

	/*
	 * Commit the repair transaction and drop the ILOCK so that we can
	 * use individual transactions to re-add each extended attribute.
	 */
	error = xfs_trans_commit(rx->sc->tp);
	rx->sc->tp = NULL;
	if (error)
		return error;

	/*
	 * Drop the ILOCK so that we can use the atomic extent swapping
	 * functions, which help us to compute the correct block reservations
	 * and lock the inodes.
	 *
	 * We still hold the IOLOCK (aka i_rwsem) which will prevent attr
	 * modifications, but there's nothing to prevent userspace from
	 * reading/listing the attrs while we build a new attr fork.  Oh well,
	 * at least the fs can't shut down those threads if they stumble into
	 * corrupt blocks.
	 */
	xfs_iunlock(rx->sc->ip, XFS_ILOCK_EXCL);
	xfs_iunlock(rx->sc->tempip, XFS_ILOCK_EXCL);
	rx->sc->ilock_flags &= ~XFS_ILOCK_EXCL;
	rx->sc->temp_ilock_flags &= ~XFS_ILOCK_EXCL;

	/*
	 * Swap the tempfile's attr fork with the file being repaired.  This
	 * recreates the transaction and re-takes the ILOCK in the scrub
	 * context.
	 */
	error = xrep_xattr_swap(rx);
	if (error)
		return error;

	/*
	 * Now wipe out the attr fork of the temp file so that regular inode
	 * inactivation won't trip over the corrupt attr fork.
	 */
	return xrep_xattr_reset_fork(rx->sc, rx->sc->tempip);
}

/*
 * Repair the extended attribute metadata.
 *
 * XXX: Remote attribute value buffers encompass the entire (up to 64k) buffer.
 * The buffer cache in XFS can't handle aliased multiblock buffers, so this
 * might misbehave if the attr fork is crosslinked with other filesystem
 * metadata.
 */
int
xrep_xattr(
	struct xfs_scrub	*sc)
{
	struct xrep_xattr	rx = {
		.sc		= sc,
	};
	int			max_len;
	int			error;

	if (!xfs_inode_hasattr(sc->ip))
		return -ENOENT;

	/*
	 * Make sure we have enough space to handle salvaging and spilling
	 * every possible local attr value, since we only realloc the buffer
	 * for remote values.
	 */
	max_len = xfs_attr_leaf_entsize_local_max(sc->mp->m_attr_geo->blksize);
	error = xrep_setup_xattr_buf(sc, max_len, false);
	if (error == -ENOMEM)
		return -EDEADLOCK;
	if (error)
		return error;

	/* Set up some storage */
	rx.xattr_records = xfbma_init("xattr keys",
			sizeof(struct xrep_xattr_key));
	if (IS_ERR(rx.xattr_records))
		return PTR_ERR(rx.xattr_records);
	rx.xattr_blobs = xblob_init("xattr values");
	if (IS_ERR(rx.xattr_blobs)) {
		error = PTR_ERR(rx.xattr_blobs);
		goto out_arr;
	}

	/*
	 * Cycle the ILOCK here so that we can lock both the file we're
	 * repairing as well as the tempfile we created earlier.
	 */
	if (sc->ilock_flags & XFS_ILOCK_EXCL)
		xfs_iunlock(sc->ip, XFS_ILOCK_EXCL);
	xfs_lock_two_inodes(sc->ip, XFS_ILOCK_EXCL, sc->tempip,
			XFS_ILOCK_EXCL);
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	sc->temp_ilock_flags |= XFS_ILOCK_EXCL;

	/* Collect extended attributes by parsing raw blocks. */
	error = xrep_xattr_find_attributes(&rx);
	if (error)
		goto out;

	/*
	 * Now that we've stuffed all the salvaged attributes in the temporary
	 * file, drop the in-memory staging areas.  Hang on to both ILOCKs.
	 */
	xblob_destroy(rx.xattr_blobs);
	xfbma_destroy(rx.xattr_records);
	rx.xattr_blobs = NULL;
	rx.xattr_records = NULL;

	/* Now rebuild the attribute information. */
	return xrep_xattr_rebuild_tree(&rx);
out:
	xblob_destroy(rx.xattr_blobs);
out_arr:
	xfbma_destroy(rx.xattr_records);
	return error;
}
