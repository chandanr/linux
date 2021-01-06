/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_SCRUB_XFILE_H__
#define __XFS_SCRUB_XFILE_H__

struct xfile {
	struct file	*file;
};

struct xfile *xfile_create(const char *description, loff_t size);
void xfile_destroy(struct xfile *xf);

int xfile_pread(struct xfile *xf, void *buf, size_t count, loff_t offset);
int xfile_pwrite(struct xfile *xf, void *buf, size_t count, loff_t offset);

void xfile_discard(struct xfile *xf, loff_t start, loff_t end);
loff_t xfile_seek_data(struct xfile *xf, loff_t pos);
int xfile_statx(struct xfile *xf, struct kstat *statbuf);

#endif /* __XFS_SCRUB_XFILE_H__ */
