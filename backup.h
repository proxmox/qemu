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

#include <uuid/uuid.h>
#include "block/block.h"

#define BACKUP_CLUSTER_BITS 16
#define BACKUP_CLUSTER_SIZE (1<<BACKUP_CLUSTER_BITS)
#define BACKUP_BLOCKS_PER_CLUSTER (BACKUP_CLUSTER_SIZE/BDRV_SECTOR_SIZE)

typedef int BackupDumpFunc(void *opaque, BlockDriverState *bs,
                           int64_t cluster_num, unsigned char *buf);

void backup_job_start(BlockDriverState *bs, bool cancel);

int backup_job_create(BlockDriverState *bs, BackupDumpFunc *backup_dump_cb,
                      BlockDriverCompletionFunc *backup_complete_cb,
                      void *opaque, int64_t speed);

typedef struct BackupDriver {
    const char *format;
    void *(*open)(const char *filename, uuid_t uuid, Error **errp);
    int (*close)(void *opaque, Error **errp);
    int (*register_config)(void *opaque, const char *name, gpointer data,
                              size_t data_len);
    int (*register_stream)(void *opaque, const char *devname, size_t size);
    int (*dump)(void *opaque, uint8_t dev_id, int64_t cluster_num,
                   unsigned char *buf, size_t *zero_bytes);
    int (*complete)(void *opaque, uint8_t dev_id, int ret);
} BackupDriver;

#endif /* QEMU_BACKUP_H */
