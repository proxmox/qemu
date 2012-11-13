/*
 * QEMU backup related definitions
 *
 * Copyright (C) 2013 Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_BACKUP_H
#define QEMU_BACKUP_H

#define BACKUP_CLUSTER_BITS 16
#define BACKUP_CLUSTER_SIZE (1<<BACKUP_CLUSTER_BITS)
#define BACKUP_BLOCKS_PER_CLUSTER (BACKUP_CLUSTER_SIZE/BDRV_SECTOR_SIZE)

typedef int BackupDumpFunc(void *opaque, BlockDriverState *bs,
                           int64_t cluster_num, unsigned char *buf);

void backup_job_start(BlockDriverState *bs, bool cancel);

int backup_job_create(BlockDriverState *bs, BackupDumpFunc *backup_dump_cb,
                      BlockDriverCompletionFunc *backup_complete_cb,
                      void *opaque, int64_t speed);

#endif /* QEMU_BACKUP_H */
