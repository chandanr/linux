// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "scrub/array.h"
#include "scrub/blob.h"
#include "scrub/xfile.h"

/*
 * XFS Blob Storage
 * ================
 * Stores and retrieves blobs using a memfd object.  Objects are appended to
 * the file and the offset is returned as a magic cookie for retrieval.
 */

#define XB_KEY_MAGIC	0xABAADDAD
struct xb_key {
	uint32_t		magic;
	uint32_t		size;
	loff_t			offset;
	/* blob comes after here */
} __packed;

/* Initialize a blob storage object. */
struct xblob *
xblob_init(
	const char	*description)
{
	struct xblob	*blob;
	struct xfile	*xfile;
	int		error;

	xfile = xfile_create(description, 0);
	if (IS_ERR(xfile))
		return ERR_CAST(xfile);

	error = -ENOMEM;
	blob = kmem_alloc(sizeof(struct xblob), KM_NOFS | KM_MAYFAIL);
	if (!blob)
		goto out_xfile;

	blob->xfile = xfile;
	blob->last_offset = PAGE_SIZE;
	return blob;
out_xfile:
	xfile_destroy(xfile);
	return ERR_PTR(error);
}

/* Destroy a blob storage object. */
void
xblob_destroy(
	struct xblob	*blob)
{
	xfile_destroy(blob->xfile);
	kmem_free(blob);
}

/* Retrieve a blob. */
int
xblob_get(
	struct xblob	*blob,
	xblob_cookie	cookie,
	void		*ptr,
	uint32_t	size)
{
	struct xb_key	key;
	int		error;

	error = xfile_pread(blob->xfile, &key, sizeof(key), cookie);
	if (error)
		return error;

	if (key.magic != XB_KEY_MAGIC || key.offset != cookie) {
		ASSERT(0);
		return -ENODATA;
	}
	if (size < key.size) {
		ASSERT(0);
		return -EFBIG;
	}

	return xfile_pread(blob->xfile, ptr, key.size, cookie + sizeof(key));
}

/* Store a blob. */
int
xblob_put(
	struct xblob	*blob,
	xblob_cookie	*cookie,
	void		*ptr,
	uint32_t	size)
{
	struct xb_key	key = {
		.offset = blob->last_offset,
		.magic = XB_KEY_MAGIC,
		.size = size,
	};
	loff_t		pos = blob->last_offset;
	int		error;

	error = xfile_pwrite(blob->xfile, &key, sizeof(key), pos);
	if (error)
		goto out_err;

	pos += sizeof(key);
	error = xfile_pwrite(blob->xfile, ptr, size, pos);
	if (error)
		goto out_err;

	*cookie = blob->last_offset;
	blob->last_offset += sizeof(key) + size;
	return 0;
out_err:
	xfile_discard(blob->xfile, blob->last_offset, pos - 1);
	return -ENOMEM;
}

/* Free a blob. */
int
xblob_free(
	struct xblob	*blob,
	xblob_cookie	cookie)
{
	struct xb_key	key;
	int		error;

	error = xfile_pread(blob->xfile, &key, sizeof(key), cookie);
	if (error)
		return error;

	if (key.magic != XB_KEY_MAGIC || key.offset != cookie) {
		ASSERT(0);
		return -ENODATA;
	}

	xfile_discard(blob->xfile, cookie, cookie + sizeof(key) + key.size - 1);
	return 0;
}

/* How many bytes is this blob storage object consuming? */
loff_t
xblob_bytes(
	struct xblob	*blob)
{
	struct kstat	statbuf;
	int		ret;

	ret = xfile_statx(blob->xfile, &statbuf);
	if (ret)
		return ret;

	return statbuf.blocks * 512;
}

/* Drop all the blobs. */
void
xblob_truncate(
	struct xblob	*blob)
{
	xfile_discard(blob->xfile, 0, MAX_LFS_FILESIZE);
	blob->last_offset = 0;
}
