/*
 * VMA: Virtual Machine Archive
 *
 * Copyright (C) 2012 Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <glib.h>

#include "qemu-common.h"
#include "qemu/error-report.h"
#include "vma.h"
#include "block/block.h"
#include "block/nbd.h"

static void help(void)
{
    const char *help_msg =
        "usage: vma command [command options]\n"
        "\n"
        "vma list <archive>\n"
        "vma create [-c config] <archive> pathname ...\n"
        "vma dumper [-c config] <archive> [-socket path] ...\n"
        "vma extract <archive> [-r] <targetdir>\n"
        ;

    printf("%s", help_msg);
    exit(1);
}

static const char *extract_devname(const char *path, char **devname, int index)
{
    assert(path);

    const char *sep = strchr(path, '=');

    if (sep) {
        *devname = g_strndup(path, sep - path);
        path = sep + 1;
    } else {
        if (index >= 0) {
            *devname = g_strdup_printf("disk%d", index);
        } else {
            *devname = NULL;
        }
    }

    return path;
}

static size_t extract_devsize(const char *path, char **devname)
{
    assert(path);

    const char *sep = strchr(path, ':');

    if (sep) {
        if (*(sep + 1) != 0) {
            char *p;
            size_t size = strtoll(sep + 1, &p, 10);
            if (*p == 0) {
                *devname = g_strndup(path, sep - path);
                return size;
            }
        } 
    }

    *devname = NULL;
    return -1;
}

static void print_content(VmaReader *vmar)
{
    assert(vmar);

    VmaHeader *head = vma_reader_get_header(vmar);

    GList *l = vma_reader_get_config_data(vmar);
    while (l && l->data) {
        VmaConfigData *cdata = (VmaConfigData *)l->data;
        l = g_list_next(l);
        printf("CFG: size: %d name: %s\n", cdata->len, cdata->name);
    }

    int i;
    VmaDeviceInfo *di;
    for (i = 1; i < 255; i++) {
        di = vma_reader_get_device_info(vmar, i);
        if (di) {
            if (strcmp(di->devname, "vmstate") == 0) {
                printf("VMSTATE: dev_id=%d memory: %zd\n", i, di->size);
            } else {
                printf("DEV: dev_id=%d size: %zd devname: %s\n",
                       i, di->size, di->devname);
            }
        }
    }
    /* ctime is the last entry we print */
    printf("CTIME: %s", ctime(&head->ctime));
    fflush(stdout);
}

static int list_content(int argc, char **argv)
{
    int c, ret = 0;
    const char *filename;

    for (;;) {
        c = getopt(argc, argv, "h");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        default:
            g_assert_not_reached();
        }
    }

    /* Get the filename */
    if ((optind + 1) != argc) {
        help();
    }
    filename = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    print_content(vmar);

    vma_reader_destroy(vmar);

    return ret;
}

typedef struct RestoreMap {
    char *devname;
    char *path;
    bool write_zero;
} RestoreMap;

static int extract_content(int argc, char **argv)
{
    int c, ret = 0;
    int verbose = 0;
    const char *filename;
    const char *dirname;
    const char *readmap = NULL;

    for (;;) {
        c = getopt(argc, argv, "hvr:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'r':
            readmap = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            help();
        }
    }

    /* Get the filename */
    if ((optind + 2) != argc) {
        help();
    }
    filename = argv[optind++];
    dirname = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    if (mkdir(dirname, 0777) < 0) {
        g_error("unable to create target directory %s - %s",
                dirname, g_strerror(errno));
    }

    GList *l = vma_reader_get_config_data(vmar);
    while (l && l->data) {
        VmaConfigData *cdata = (VmaConfigData *)l->data;
        l = g_list_next(l);
        char *cfgfn = g_strdup_printf("%s/%s", dirname, cdata->name);
        GError *err = NULL;
        if (!g_file_set_contents(cfgfn, (gchar *)cdata->data, cdata->len,
                                 &err)) {
            g_error("unable to write file: %s", err->message);
        }
    }

    GHashTable *devmap = g_hash_table_new(g_str_hash, g_str_equal);

    if (readmap) {
        print_content(vmar);

        FILE *map = fopen(readmap, "r");
        if (!map) {
            g_error("unable to open fifo %s - %s", readmap, g_strerror(errno));
        }

        while (1) {
            char inbuf[8192];
            char *line = fgets(inbuf, sizeof(inbuf), map);
            if (!line || line[0] == '\0' || !strcmp(line, "done\n")) {
                break;
            }
            int len = strlen(line);
            if (line[len - 1] == '\n') {
                line[len - 1] = '\0';
                if (len == 1) {
                    break;
                }
            }

            const char *path;
            bool write_zero;
            if (line[0] == '0' && line[1] == ':') {
                path = inbuf + 2;
                write_zero = false;
            } else if (line[0] == '1' && line[1] == ':') {
                path = inbuf + 2;
                write_zero = true;
            } else {
                g_error("read map failed - parse error ('%s')", inbuf);
            }

            char *devname = NULL;
            path = extract_devname(path, &devname, -1);
            if (!devname) {
                g_error("read map failed - no dev name specified ('%s')",
                        inbuf);
            }

            RestoreMap *map = g_new0(RestoreMap, 1);
            map->devname = g_strdup(devname);
            map->path = g_strdup(path);
            map->write_zero = write_zero;

            g_hash_table_insert(devmap, map->devname, map);

        };
    }

    int i;
    int vmstate_fd = -1;
    guint8 vmstate_stream = 0;

    for (i = 1; i < 255; i++) {
        VmaDeviceInfo *di = vma_reader_get_device_info(vmar, i);
        if (di && (strcmp(di->devname, "vmstate") == 0)) {
            vmstate_stream = i;
            char *statefn = g_strdup_printf("%s/vmstate.bin", dirname);
            vmstate_fd = open(statefn, O_WRONLY|O_CREAT|O_EXCL, 0644);
            if (vmstate_fd < 0) {
                g_error("create vmstate file '%s' failed - %s", statefn,
                        g_strerror(errno));
            }
            g_free(statefn);
        } else if (di) {
            char *devfn = NULL;
            int flags = BDRV_O_RDWR|BDRV_O_CACHE_WB;
            bool write_zero = true;

            if (readmap) {
                RestoreMap *map;
                map = (RestoreMap *)g_hash_table_lookup(devmap, di->devname);
                if (map == NULL) {
                    g_error("no device name mapping for %s", di->devname);
                }
                devfn = map->path;
                write_zero = map->write_zero;
            } else {
                devfn = g_strdup_printf("%s/tmp-disk-%s.raw",
                                        dirname, di->devname);
                printf("DEVINFO %s %zd\n", devfn, di->size);

                bdrv_img_create(devfn, "raw", NULL, NULL, NULL, di->size,
                                flags, &errp);
                if (error_is_set(&errp)) {
                    g_error("can't create file %s: %s", devfn,
                            error_get_pretty(errp));
                }

                /* Note: we created an empty file above, so there is no
                 * need to write zeroes (so we generate a sparse file)
                 */
                write_zero = false;
            }

            BlockDriverState *bs = bdrv_new(di->devname);
            if (bdrv_open(bs, devfn, flags, NULL)) {
                g_error("can't open file %s", devfn);
            }
            if (vma_reader_register_bs(vmar, i, bs, write_zero, &errp) < 0) {
                g_error("%s", error_get_pretty(errp));
            }

            if (!readmap) {
                g_free(devfn);
            }
        }
    }

    if (vma_reader_restore(vmar, vmstate_fd, verbose, &errp) < 0) {
        g_error("restore failed - %s", error_get_pretty(errp));
    }

    if (!readmap) {
        for (i = 1; i < 255; i++) {
            VmaDeviceInfo *di = vma_reader_get_device_info(vmar, i);
            if (di && (i != vmstate_stream)) {
                char *tmpfn = g_strdup_printf("%s/tmp-disk-%s.raw",
                                              dirname, di->devname);
                char *fn = g_strdup_printf("%s/disk-%s.raw",
                                           dirname, di->devname);
                if (rename(tmpfn, fn) != 0) {
                    g_error("rename %s to %s failed - %s",
                            tmpfn, fn, g_strerror(errno));
                }
            }
        }
    }

    vma_reader_destroy(vmar);

    bdrv_close_all();

    return ret;
}

typedef struct BackupCB {
    VmaWriter *vmaw;
    uint8_t dev_id;
} BackupCB;

static int backup_dump_cb(void *opaque, BlockDriverState *bs,
                          int64_t cluster_num, unsigned char *buf)
{
    BackupCB *bcb = opaque;
    size_t zb = 0;
    if (vma_writer_write(bcb->vmaw, bcb->dev_id, cluster_num, buf, &zb) < 0) {
        g_warning("backup_dump_cb vma_writer_write failed");
        return -1;
    }

    return 0;
}

static void backup_complete_cb(void *opaque, int ret)
{
    BackupCB *bcb = opaque;

    if (ret < 0) {
        vma_writer_set_error(bcb->vmaw, "backup_complete_cb %d", ret);
    }

    if (vma_writer_close_stream(bcb->vmaw, bcb->dev_id) <= 0) {
        Error *err = NULL;
        if (vma_writer_close(bcb->vmaw, &err) != 0) {
            g_warning("vma_writer_close failed %s", error_get_pretty(err));
        }
    }
}

static int create_archive(int argc, char **argv)
{
    int i, c, res;
    int verbose = 0;
    const char *archivename;
    GList *config_files = NULL;

    for (;;) {
        c = getopt(argc, argv, "hvc:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'c':
            config_files = g_list_append(config_files, optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            g_assert_not_reached();
        }
    }


    /* make sure we have archive name and at least one path */
    if ((optind + 2) > argc) {
        help();
    }

    archivename = argv[optind++];

    uuid_t uuid;
    uuid_generate(uuid);

    Error *local_err = NULL;
    VmaWriter *vmaw = vma_writer_create(archivename, uuid, &local_err);

    if (vmaw == NULL) {
        g_error("%s", error_get_pretty(local_err));
    }

    GList *l = config_files;
    while (l && l->data) {
        char *name = l->data;
        char *cdata = NULL;
        gsize clen = 0;
        GError *err = NULL;
        if (!g_file_get_contents(name, &cdata, &clen, &err)) {
            unlink(archivename);
            g_error("Unable to read file: %s", err->message);
        }

        if (vma_writer_add_config(vmaw, name, cdata, clen) != 0) {
            unlink(archivename);
            g_error("Unable to append config data %s (len = %zd)",
                    name, clen);
        }
        l = g_list_next(l);
    }

    int ind = 0;
    while (optind < argc) {
        const char *path = argv[optind++];
        char *devname = NULL;
        path = extract_devname(path, &devname, ind++);

        BlockDriver *drv = NULL;
        BlockDriverState *bs = bdrv_new(devname);

        res = bdrv_open(bs, path, BDRV_O_CACHE_WB , drv);
        if (res < 0) {
            unlink(archivename);
            g_error("bdrv_open '%s' failed", path);
        }
        int64_t size = bdrv_getlength(bs);
        int dev_id = vma_writer_register_stream(vmaw, devname, size);
        if (dev_id <= 0) {
            unlink(archivename);
            g_error("vma_writer_register_stream '%s' failed", devname);
        }

        BackupCB *bcb = g_new0(BackupCB, 1);
        bcb->vmaw = vmaw;
        bcb->dev_id = dev_id;

        if (backup_job_create(bs, backup_dump_cb, backup_complete_cb,
                              bcb, 0) < 0) {
            unlink(archivename);
            g_error("backup_job_start failed");
        } else {
            backup_job_start(bs, false);
        }
    }

    VmaStatus vmastat;
    int percent = 0;
    int last_percent = -1;

    while (1) {
        main_loop_wait(false);
        vma_writer_get_status(vmaw, &vmastat);

        if (verbose) {

            uint64_t total = 0;
            uint64_t transferred = 0;
            uint64_t zero_bytes = 0;

            int i;
            for (i = 0; i < 256; i++) {
                if (vmastat.stream_info[i].size) {
                    total += vmastat.stream_info[i].size;
                    transferred += vmastat.stream_info[i].transferred;
                    zero_bytes += vmastat.stream_info[i].zero_bytes;
                }
            }
            percent = (transferred*100)/total;
            if (percent != last_percent) {
                fprintf(stderr, "progress %d%% %zd/%zd %zd\n", percent,
                        transferred, total, zero_bytes);
                fflush(stderr);

                last_percent = percent;
            }
        }

        if (vmastat.closed) {
            break;
        }
    }

    bdrv_drain_all();

    vma_writer_get_status(vmaw, &vmastat);

    if (verbose) {
        for (i = 0; i < 256; i++) {
            VmaStreamInfo *si = &vmastat.stream_info[i];
            if (si->size) {
                fprintf(stderr, "image %s: size=%zd zeros=%zd saved=%zd\n",
                        si->devname, si->size, si->zero_bytes,
                        si->size - si->zero_bytes);
            }
        }
    }

    if (vmastat.status < 0) {
        unlink(archivename);
        g_error("creating vma archive failed");
    }

    return 0;
}

static enum { WAITING, RUNNING, TERMINATE, TERMINATING, TERMINATED } state;
static int nbd_clients = 0;
static GList *nbd_exports = NULL;
QEMUTimer *nbd_connect_timer = NULL;

static void nbd_set_state(int new_state)
{
    state = new_state;
    qemu_notify_event();
}

static int nbd_can_accept(void *opaque)
{
    return (g_list_length(nbd_exports) > nbd_clients) ;
}

static void nbd_export_closed(NBDExport *exp)
{
    nbd_exports = g_list_remove(nbd_exports, exp);

    if (g_list_length(nbd_exports) == 0) {
        g_message("nbd_export_closed all exports closed");
        assert(state == TERMINATING);
        nbd_set_state(TERMINATED);
    }
}

static void nbd_client_closed(NBDClient *client)
{

    g_message("nbd_client_closed");

    nbd_clients--;

    if (nbd_clients <= 0 && state == RUNNING) {
        g_message("nbd_client_closed all clients closed");
        nbd_set_state(TERMINATE);
    }

    nbd_client_put(client);
}

static void nbd_accept(void *opaque)
{
    int server_fd = (uintptr_t) opaque;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);

    if (fd < 0) {
        g_error("nbd_accept failed");
    }

    if (state >= TERMINATE) {
        close(fd);
        return;
    }


    NBDClient *client = nbd_client_new(NULL, fd, nbd_client_closed);
    if (!client) {
        g_error("nbd_accept nbd_client_new failed");
    }

    nbd_clients++;

    if (state == WAITING && (nbd_clients == g_list_length(nbd_exports))) {
        nbd_set_state(RUNNING);
    }

    g_message("nbd_accept done");
}

static int nbd_write_cb(void *opaque, int64_t sector_num,
                        const uint8_t *buf, int nb_sectors)
{
    BackupCB *bcb = opaque;
    size_t zb = 0;

    return 0;

    if (state == WAITING) {
        g_warning("nbd_write_cb: received write while waiting for connections");
        goto err;
    } else if (state != RUNNING) {
        goto err;
    }

    if (nb_sectors != (VMA_CLUSTER_SIZE/512)) {
        g_warning("nbd_write_cb: wrong block size");
        goto err;
    }

    if (sector_num % (VMA_CLUSTER_SIZE/512)) {
        g_warning("nbd_write_cb: wrong cluster alignment");
        goto err;
    }
    int64_t cluster_num = sector_num/(VMA_CLUSTER_SIZE/512);
    if (vma_writer_write(bcb->vmaw, bcb->dev_id, cluster_num, buf, &zb) < 0) {
        g_warning("backup_dump_cb vma_writer_write failed");
        // fixme: what do do
        return -1;
    }

    return nb_sectors;

err:
    nbd_set_state(TERMINATE); 
    return -1;
}

static void nbd_timeout_cb(void *opaque)
{
    if (state == WAITING) {
        g_message("got timeout - terminate now\n");
        nbd_set_state(TERMINATE);
    }
} 

static int create_archive2(int argc, char **argv)
{
    int c;
    int verbose = 0;
    const char *archivename;
    GList *config_files = NULL;

    const char *sockpath = "/tmp/vmaw.sock"; // fixme:
    //const char *bindto = "0.0.0.0";

    for (;;) {
        c = getopt(argc, argv, "hvc:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'c':
            config_files = g_list_append(config_files, optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            g_assert_not_reached();
        }
    }

    /* make sure we have archive name and at least one path */
    if ((optind + 2) > argc) {
        help();
    }

    archivename = argv[optind++];

    uuid_t uuid;
    uuid_generate(uuid);

    Error *local_err = NULL;
    VmaWriter *vmaw = vma_writer_create(archivename, uuid, &local_err);

    if (vmaw == NULL) {
        g_error("%s", error_get_pretty(local_err));
    }

    GList *l = config_files;
    while (l && l->data) {
        char *name = l->data;
        char *cdata = NULL;
        gsize clen = 0;
        GError *err = NULL;
        if (!g_file_get_contents(name, &cdata, &clen, &err)) {
            unlink(archivename);
            g_error("Unable to read file: %s", err->message);
        }

        if (vma_writer_add_config(vmaw, name, cdata, clen) != 0) {
            unlink(archivename);
            g_error("Unable to append config data %s (len = %zd)",
                    name, clen);
        }
        l = g_list_next(l);
    }

    while (optind < argc) {
        const char *path = argv[optind++];
        char *devname = NULL;

        size_t size =  extract_devsize(path, &devname);
        printf("TEST %s %zd\n", devname, size);

        int dev_id = vma_writer_register_stream(vmaw, devname, size);
        if (dev_id <= 0) {
            unlink(archivename);
            g_error("vma_writer_register_stream '%s' failed", devname);
        }

        BackupCB *bcb = g_new0(BackupCB, 1);
        bcb->vmaw = vmaw;
        bcb->dev_id = dev_id;

        NBDExport *exp = nbd_export2_new(size, NBD_FLAG_SEND_TRIM, 
                                         nbd_write_cb, bcb, nbd_export_closed);
        nbd_export_set_name(exp, devname);
        nbd_exports = g_list_append(nbd_exports, exp);
    }

    int fd = unix_socket_incoming(sockpath);
    //int fd = tcp_socket_incoming(bindto, 12340);

    if (fd < 0) {
        g_error("unable to open socked '%s' - %s", sockpath, 
                g_strerror(errno));
    }

    qemu_set_fd_handler2(fd, nbd_can_accept, nbd_accept, NULL,
                         (void *)(uintptr_t)fd);

    nbd_set_state(WAITING);

    int64_t timeout = 10;
    nbd_connect_timer = qemu_new_timer_ns(rt_clock, nbd_timeout_cb, NULL);
    qemu_mod_timer(nbd_connect_timer, qemu_get_clock_ns(rt_clock) + 
                   (timeout * 1000000000));
               
    VmaStatus vmastat;
    int percent = 0;
    int last_percent = -1;
    do {
        main_loop_wait(false);
        if (state == TERMINATE) {
            nbd_set_state(TERMINATING);
            GList *l = nbd_exports;
            while (l) {
                NBDExport *exp = (NBDExport *)l->data;
                l = g_list_next(l);
                nbd_export_close(exp);
                nbd_export_put(exp);
            }
            g_list_free(nbd_exports);
            nbd_exports = NULL;
        }
 
        vma_writer_get_status(vmaw, &vmastat);

        if (verbose) {
            uint64_t total = 0;
            uint64_t transferred = 0;
            uint64_t zero_bytes = 0;

            int i;
            for (i = 0; i < 256; i++) {
                if (vmastat.stream_info[i].size) {
                    total += vmastat.stream_info[i].size;
                    transferred += vmastat.stream_info[i].transferred;
                    zero_bytes += vmastat.stream_info[i].zero_bytes;
                }
            }
            percent = (transferred*100)/total;
            if (percent != last_percent) {
                fprintf(stderr, "progress %d%% %zd/%zd %zd\n", percent,
                        transferred, total, zero_bytes);
                fflush(stderr);

                last_percent = percent;
            }
        }

        if (vmastat.closed) {
            nbd_set_state(TERMINATE);
        }
    } while (state != TERMINATED);

    if (sockpath) {
        unlink(sockpath);
    }

    bdrv_drain_all();

    vma_writer_get_status(vmaw, &vmastat);

    if (verbose) {
        int i;
        for (i = 0; i < 256; i++) {
            VmaStreamInfo *si = &vmastat.stream_info[i];
            if (si->size) {
                fprintf(stderr, "image %s: size=%zd zeros=%zd saved=%zd\n",
                        si->devname, si->size, si->zero_bytes,
                        si->size - si->zero_bytes);
            }
        }
    }

    if (vmastat.status < 0) {
        unlink(archivename);
        g_error("creating vma archive failed");
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *cmdname;

    error_set_progname(argv[0]);

    g_thread_init(NULL);

    qemu_init_main_loop();

    bdrv_init();

    if (argc < 2) {
        help();
    }

    cmdname = argv[1];
    argc--; argv++;

    if (!strcmp(cmdname, "list")) {
        return list_content(argc, argv);
    } else if (!strcmp(cmdname, "create")) {
        return create_archive(argc, argv);
    } else if (!strcmp(cmdname, "dumper")) {
        return create_archive2(argc, argv);
     } else if (!strcmp(cmdname, "extract")) {
        return extract_content(argc, argv);
    }

    help();
    return 0;
}
