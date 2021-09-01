/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_SCRUB_BLOB_H__
#define __XFS_SCRUB_BLOB_H__

struct xblob {
	struct xfile	*xfile;
	loff_t		last_offset;
};

typedef loff_t		xblob_cookie;

struct xblob *xblob_init(const char *descr);
void xblob_destroy(struct xblob *blob);
int xblob_get(struct xblob *blob, xblob_cookie cookie, void *ptr,
		uint32_t size);
int xblob_put(struct xblob *blob, xblob_cookie *cookie, void *ptr,
		uint32_t size);
int xblob_free(struct xblob *blob, xblob_cookie cookie);
loff_t xblob_bytes(struct xblob *blob);
void xblob_truncate(struct xblob *blob);

#endif /* __XFS_SCRUB_BLOB_H__ */
