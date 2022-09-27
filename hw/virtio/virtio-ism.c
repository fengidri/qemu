/*
 * Virtio ISM device
 *
 * Copyright (c) 2021 Alibaba Group.
 *
 * Authors:  Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qemu/qht.h"
#include "qemu/sockets.h"
#include "sysemu/numa.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "sysemu/iothread.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-access.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include "migration/misc.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include CONFIG_DEVICES
#include "trace.h"
#include <sys/stat.h>
#include <sys/types.h>

#include "hw/pci/msix.h"
#include "standard-headers/linux/virtio_pci.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-ism.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"

static VirtISM *devlist[256];
static int devindex;

struct msg_id {
    int devid;
    int pos;
};

//#define printf(...)

static int sendfd(int unix_fd, int target_fd, struct msg_id *m)
{
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = { NULL, };
    struct iovec    iov[1];
    struct cmsghdr *cmsg;

    memset(control, 0, CMSG_SPACE(sizeof(int)));

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    iov[0].iov_base = m;
    iov[0].iov_len = sizeof(*m);

    if (target_fd != -1) {
        msg.msg_control = control;
        msg.msg_controllen = CMSG_SPACE(sizeof(int));

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;


        *(int *)CMSG_DATA(cmsg) = target_fd;
    }

    return sendmsg(unix_fd, &msg, 0);
}

static int recvfd(int unix_fd, int *target_fd, struct msg_id *m)
{
    struct msghdr msg = { NULL, };
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov[1];
    struct cmsghdr *cmsg;
    int ret;

    *target_fd = -1;

    memset(control, 0, CMSG_SPACE(sizeof(int)));

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    iov[0].iov_base = m;
    iov[0].iov_len = sizeof(*m);

    ret = recvmsg(unix_fd, &msg, 0);
    if (ret < 0)
        return ret;

    if (!msg.msg_controllen)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
        cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS)
    {
        return ret;
    }

    *target_fd = *(int *)CMSG_DATA(cmsg);

    return ret;
}

typedef struct GSourceServer {
    GSource source;
    GIOChannel *channel;
    GPollFD fd;
} GSourceServer;

static gboolean g_source_prepare(GSource * source, gint * timeout)
{
    *timeout = -1;

    return FALSE;
}

static gboolean g_source_check(GSource * source)
{
    GSourceServer *s = (GSourceServer *) source;

    if (s->fd.revents != s->fd.events) {
        return FALSE;
    }

    return TRUE;
}

static gboolean g_source_dispatch(GSource * source,
                                  GSourceFunc callback, gpointer user_data)
{
    gboolean again = G_SOURCE_REMOVE;

    GSourceServer *s = (GSourceServer *) source;

    if (callback) {
        again = callback(s);
    }

    return again;
}

static void g_source_finalize(GSource * source)
{
    GSourceServer *s = (GSourceServer *) source;

    if (s->channel) {
        g_io_channel_unref(s->channel);
    }
}

static GSourceFuncs g_s_funcs = {
    g_source_prepare,
    g_source_check,
    g_source_dispatch,
    g_source_finalize,
};

static gboolean server_handler(GSourceServer *s)
{
    struct virtio_ism_chunk *c;
    struct VirtISMRegion *r;
    int fd, ret, irqfd;
    struct msg_id m;
    VirtISM *ism;

    fd = accept(s->fd.fd, NULL, NULL);

    ret = recvfd(fd, &irqfd, &m);
    if (ret < 0) {
        close(fd);
        return ret;
    }

    ism = devlist[m.devid];
    c = ism->chunks + m.pos;
    r = c->region;

    if (irqfd != -1) {  // attach
        r->peer_irqfd = irqfd;
        irqfd = event_notifier_get_wfd(&r->notifier->notifier);
    } else { // detach
        close(r->peer_irqfd);
        r->peer_irqfd = -1;
    }

//    printf("recv from unix socket: %d %d recv irqfd: %d send irqfd: %d\n",
//           m.devid, m.pos, r->peer_irqfd, irqfd);

    sendfd(fd, irqfd, &m);

    close(fd);

    return TRUE;
}

static int server_connect(int pid)
{
    SocketAddress addr = {};
    char buf[512];
    Error *e;

    snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/server-%d", pid);

    addr.type = SOCKET_ADDRESS_TYPE_UNIX;
    addr.u.q_unix.path = buf;
    addr.u.q_unix.abstract = true;
    addr.u.q_unix.has_abstract = true;

    return socket_connect(&addr, &e);
}

static int create_server(void)
{
    static int done;
    char buf[512];
    Error *err;
    int sock;
    Error *error_abort;
    IOThread *ism_iothread;
    GSource *source;
    GSourceServer *s;
    struct stat st;
    SocketAddress addr = {};

    if (qatomic_fetch_inc(&done))
        return 0;

    if (stat("/dev/shm/virtio-ism", &st) || !S_ISDIR(st.st_mode)) {
        if (mkdir("/dev/shm/virtio-ism", S_IRWXU)) {
            printf("create /dev/shm/virtio-ism fail\n");
            return -1;
        }
    }

    snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/server-%d", getpid());

    addr.type = SOCKET_ADDRESS_TYPE_UNIX;
    addr.u.q_unix.path = buf;
    addr.u.q_unix.abstract = true;
    addr.u.q_unix.has_abstract = true;

    sock = socket_listen(&addr, 512, &err);
    if (!sock) {
        printf("create unix socket fail. check for %s\n", buf);
        assert(sock);
    }

    ism_iothread = iothread_create("ism_iothread", &error_abort);
    assert(ism_iothread);

    source = g_source_new(&g_s_funcs, sizeof(GSourceServer));
    s = (GSourceServer *) source;

    s->channel = g_io_channel_unix_new(sock);
    s->fd.fd = sock;
    s->fd.events = G_IO_IN;
    g_source_add_poll(source, &s->fd);

    GMainContext *context;

    context = iothread_get_g_main_context(ism_iothread);
    assert(context);

    g_source_set_callback(source, (GSourceFunc) server_handler, NULL, NULL);

    g_source_attach(source, context);
    g_source_unref(source);
    return 0;

}

static bool __region_cmp(const void *a, const void *b)
{
    struct VirtISMRegion *r1;

    r1 = (struct VirtISMRegion *)a;

    return r1->token == (uint64_t)b;
}

#define token_hash(t) (t + (t >> 32))

#define hash_insert(ism, r)  \
    qht_insert(&ism->ht, r, token_hash(r->token), NULL)

#define hash_remove(ism, r)  \
    g_assert_true(qht_remove(&ism->ht, (void *)r, token_hash(r->token)));

#define hash_lookup(ism, token)  \
    (struct VirtISMRegion *)qht_lookup(&ism->ht, (void *)token, token_hash(token))

static int kvm_virtio_pci_vq_vector_use(VirtIOPCIProxy *proxy,
                                        unsigned int vector, VirtIOIRQFD *irqfd)
{
    int ret;

    KVMRouteChange c = kvm_irqchip_begin_route_changes(kvm_state);
    ret = kvm_irqchip_add_msi_route(&c, vector, &proxy->pci_dev);
    if (ret < 0) {
        return ret;
    }
    kvm_irqchip_commit_route_changes(&c);
    irqfd->virq = ret;

    return 0;
}

static void virtio_ism_free_notifier(VirtISM *ism, struct virtio_ism_notifier *notifier)
{
    int ret;

    --notifier->refs;

    if (notifier->refs)
        return;

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, &notifier->notifier,
                                                notifier->vector_irqfd.virq);

    kvm_irqchip_release_virq(kvm_state, notifier->vector_irqfd.virq);
    assert(ret == 0);

    event_notifier_cleanup(&notifier->notifier);

    notifier->done = false;
}

static int virtio_ism_init_notifier(VirtISM *ism, struct VirtISMRegion *r, int vector)
{
    struct virtio_ism_notifier *notifier;
    VirtIOPCIProxy *vpci_dev;
    int err;

    vpci_dev = ism->vpci_dev;


    notifier = ism->notifiers + vector;
    r->notifier = NULL;

    if (notifier->done)
        goto done;


    err = event_notifier_init(&notifier->notifier, 0);
    if (err < 0) {
        return err;
    }

    event_notifier_set_handler(&notifier->notifier, NULL);

    err = kvm_virtio_pci_vq_vector_use(vpci_dev, vector, &notifier->vector_irqfd);
    assert(!err);

    err = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, &notifier->notifier, NULL,
                                              notifier->vector_irqfd.virq);
    assert(!err);

    //printf("init irqfd: %d %d irqfd: %d\n", err1, err2, event_notifier_get_wfd(&notifier->notifier));

    notifier->done = true;

done:
    r->notifier = notifier;
    ++notifier->refs;

    return 0;
}

static uint64_t make_token(unsigned char devid, uint32_t pos)
{
    uint64_t token;
    uint64_t pid;

    pid = getpid();

    token = pid << 32;
    token += devid << 24;
    token += pos;

    return token;
}

static void parse_token(uint64_t token, int *pid, struct msg_id *m)
{
    *pid = token >> 32;
    m->devid = (token << 32) >> 56;
    m->pos = token & 0xffffff;
}

static void release_region(VirtISM *ism, struct VirtISMRegion *r)
{
    struct virtio_ism_chunk *c;
    char buf[512];
    int64_t offset;

    if (r->creator) {
        snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/shm-%lu", r->token);
        unlink(buf);
    }

    while (true) {
        if (QLIST_EMPTY(&r->chunks))
            break;

        c = QLIST_FIRST(&r->chunks);

        QLIST_REMOVE(c, node);

        QLIST_INSERT_HEAD(&ism->chunk_free, c, node);

        if (c->mmaped) {
            c->mmaped = false;

            offset = c->idx * ism->chunk_size;

            void *p = mmap(ism->shmp + offset, ism->chunk_size,
                           PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            assert(p != MAP_FAILED);
        }
    }
}

static int64_t map_region(VirtISM *ism, struct VirtISMRegion *r, uint64_t size, uint64_t area_n)
{
    struct virtio_ism_chunk *c;
    int64_t offset, off;
    char buf[512];
    int fd, chunk_n;
    struct stat sb;

    snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/shm-%lu", r->token);

    if (r->creator) {
        fd = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1)
            return -2;

        if (ftruncate(fd, size))
            return -3;
    } else {
        fd = open(buf, O_RDWR);
        if (fd == -1) {
            printf("open fail err %d %s\n", fd, buf);
            return -5;
        }
        if (fstat(fd, &sb)) {
            printf("fstat fail err %d %s\n", fd, buf);
            return -6;
        }

        size = sb.st_size;
    }

    chunk_n = size / ism->chunk_size;
    if (area_n < chunk_n) {
        close(fd);
        return -E2BIG;
    }

    while (r->chunks_n < chunk_n) {
        if (QLIST_EMPTY(&ism->chunk_free))
            goto err_free;

        c = QLIST_FIRST(&ism->chunk_free);

        QLIST_REMOVE(c, node);

        QLIST_INSERT_HEAD(&r->chunks, c, node);
        r->chunks_n += 1;
        c->region = r;
    }

    off = 0;
    QLIST_FOREACH(c, &r->chunks, node)
    {
        offset = c->idx;
        offset = offset * ism->chunk_size;

        void *p = mmap(ism->shmp + offset, ism->chunk_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
                       off);

        close(fd);

        off += ism->chunk_size;
        c->mmaped = true;

        if (p == MAP_FAILED) {
            printf("mmap fail %d fd: %d\n", errno, fd);
            goto err_free;
        }
    }

    return 0;

err_free:
    release_region(ism, r);

    return -8;
}

static int virtio_ism_attach_peer(VirtISM *ism, struct VirtISMRegion *r)
{
    struct msg_id m;
    int pid, ret;
    int sock;

    if (r->creator)
        return 0;

    parse_token(r->token, &pid, &m);

    sock = server_connect(pid);
    if (sock < 0)
        return sock;

    ret = sendfd(sock, event_notifier_get_wfd(&r->notifier->notifier), &m);
    if (ret < 0)
        return ret;

    ret = recvfd(sock, &r->peer_irqfd, &m);
    if (ret < 0)
        return ret;

    close(sock);

    return 0;
}

static int virtio_ism_detach_peer(VirtISM *ism, struct VirtISMRegion *r)
{
    int pid, ret, irqfd;
    struct msg_id m;
    int sock;

    if (r->peer_irqfd == -1)
        return 0;

    parse_token(r->token, &pid, &m);

    sock = server_connect(pid);
    if (sock < 0)
        return sock;

    close(r->peer_irqfd);
    r->peer_irqfd = -1;
    r->notifier = NULL;

    ret = sendfd(sock, -1, &m);
    if (ret < 0)
        return ret;

    ret = recvfd(sock, &irqfd, &m);
    if (ret < 0)
        return ret;

    close(sock);

    return 0;
}

static int virtio_ism_handle_event_vector(VirtISM *ism,
                                          const struct iovec *out_iov, unsigned out_num,
                                          const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_irq_vector iv;
    struct VirtISMRegion *r;
    int64_t token;
    int err;

    iov_to_buf(out_iov, out_num, 0, &iv, sizeof(iv));

    token = virtio_ldq_p(ism->vdev, &iv.token);
    r = hash_lookup(ism, token);
    if (!r)
        return -1;

    virtio_ism_init_notifier(ism, r, virtio_ldq_p(ism->vdev, &iv.vector));

    err = virtio_ism_attach_peer(ism, r);
    if (err)
        return err;

    return 0;
}

static int virtio_ism_handle_detach_mode(VirtISM *ism,
                                          const struct iovec *out_iov, unsigned out_num,
                                          const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_detach out;
    struct VirtISMRegion *r;
    int64_t token;

    iov_to_buf(out_iov, out_num, 0, &out, sizeof(out));

    token = virtio_ldq_p(ism->vdev, &out.token);

    r = hash_lookup(ism, token);
    if (!r)
        return -1;

    virtio_ism_detach_peer(ism, r);

    release_region(ism, r);

    if (r->notifier)
        virtio_ism_free_notifier(ism, r->notifier);

    r->notifier = NULL;

    hash_remove(ism, r);
    free(r);

    return 0;
}

static struct VirtISMRegion * __alloc(VirtISM *ism, uint64_t *token, uint64_t size, uint64_t area_n, int *errp)
{
    struct virtio_ism_chunk *c;
    struct VirtISMRegion *r;
    bool creator;
    int err;

    creator = !!size;

    r = malloc(sizeof(*r));
    if (!r) {
        *errp = -ENOMEM;
        return NULL;
    }

    QLIST_INIT(&r->chunks);

    if (QLIST_EMPTY(&ism->chunk_free)) {
        free(r);
        *errp = -ENOSPC;
        return NULL;
    }

    c = QLIST_FIRST(&ism->chunk_free);

    QLIST_REMOVE(c, node);

    QLIST_INSERT_HEAD(&r->chunks, c, node);
    c->region = r;
    r->chunks_n = 1;

    if (creator)
        *token = make_token(ism->devid, c->idx);

    r->token = *token;
    r->creator = creator;
    r->notifier = NULL;
    r->peer_irqfd = -1;

    err = map_region(ism, r, size, area_n);
    if (err) {
        free(r);
        *errp = err;
        return NULL;
    }

    *errp =  0;
    hash_insert(ism, r);

    r = hash_lookup(ism, r->token);
    return r;
}

static int fill_area(VirtISM *ism, struct VirtISMRegion *r, struct virtio_ism_area *area)
{
    struct virtio_ism_chunk *c;
    int i = 0;

    QLIST_FOREACH(c, &r->chunks, node)
    {
        virtio_stq_p(ism->vdev, &area[i].offset, c->idx * ism->chunk_size);
        virtio_stq_p(ism->vdev, &area[i].size, ism->chunk_size);
        i += 1;
    };

    return i;
}

static int virtio_ism_handle_attach_mode(VirtISM *ism,
                                         const struct iovec *out_iov, unsigned out_num,
                                         const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_attach_reply *reply;
    struct virtio_ism_ctrl_attach out;
    struct VirtISMRegion *r;
    uint64_t token;
    int area_n, size;
    int err, num;

    size = iov_size(in_iov, in_num) -  sizeof(unsigned char);
    area_n = (size - sizeof(*reply)) / sizeof(struct virtio_ism_area);
    reply = malloc(size);
    if (!reply)
        return -ENOMEM;

    iov_to_buf(out_iov, out_num, 0, &out, sizeof(out));

    token = virtio_ldq_p(ism->vdev, &out.token);

    r = __alloc(ism, &token, 0, area_n, &err);
    if (err) {
        free(reply);
        return err;
    }

    num = fill_area(ism, r, reply->area);
    virtio_stq_p(ism->vdev, &reply->num, num);

    iov_from_buf(in_iov, in_num, sizeof(unsigned char), reply, size);

    free(reply);
    return size;
}

static int virtio_ism_handle_alloc_mode(VirtISM *ism,
                                        const struct iovec *out_iov, unsigned out_num,
                                        const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_alloc_reply *reply;
    struct virtio_ism_ctrl_alloc in;
    struct VirtISMRegion *r;
    int area_n, size, num;
    uint64_t token, len;
    int err;


    size = iov_size(in_iov, in_num) -  sizeof(unsigned char);
    area_n = (size - sizeof(*reply)) / sizeof(struct virtio_ism_area);
    reply = malloc(size);
    if (!reply)
        return -ENOMEM;

    iov_to_buf(out_iov, out_num, 0, &in, sizeof(in));

    len = virtio_ldq_p(ism->vdev, &in.size);

    r = __alloc(ism, &token, len, area_n, &err);
    if (err) {
        free(reply);
        return err;
    }

    num = fill_area(ism, r, reply->area);

    virtio_stq_p(ism->vdev, &reply->token, token);
    virtio_stq_p(ism->vdev, &reply->num, num);

    iov_from_buf(in_iov, in_num, sizeof(unsigned char), reply, size);
    free(reply);

    return size;
}

static size_t virtio_ism_handle_ctrl_iov(VirtIODevice *vdev,
                                         const struct iovec *in_sg, unsigned in_num,
                                         const struct iovec *out_sg,
                                         unsigned out_num)
{
    VirtISM *ism = VIRTIO_ISM(vdev);
    struct virtio_ism_ctrl_hdr ctrl;
    unsigned char status = VIRTIO_ISM_ERR;
    size_t s;
    int wn = 0;
    struct iovec *iov, *iov2;

    if (iov_size(in_sg, in_num) < sizeof(status) ||
        iov_size(out_sg, out_num) < sizeof(ctrl)) {
        virtio_error(vdev, "virtio-net ctrl missing headers");
        return 0;
    }

    iov2 = iov = g_memdup2(out_sg, sizeof(struct iovec) * out_num);
    s = iov_to_buf(iov, out_num, 0, &ctrl, sizeof(ctrl));
    iov_discard_front(&iov, &out_num, sizeof(ctrl));

    if (s != sizeof(ctrl)) {
        status = VIRTIO_ISM_ERR;

        s = iov_from_buf(in_sg, in_num, 0, &status, sizeof(status));
        assert(s == sizeof(status));
        wn = sizeof(status);

    } else if (ctrl.class == VIRTIO_ISM_CTRL_ALLOC) {
        wn = virtio_ism_handle_alloc_mode(ism, iov, out_num, in_sg, in_num);

    } else if (ctrl.class == VIRTIO_ISM_CTRL_ATTACH) {
        wn = virtio_ism_handle_attach_mode(ism, iov, out_num, in_sg, in_num);

    } else if (ctrl.class == VIRTIO_ISM_CTRL_DETACH) {
        wn = virtio_ism_handle_detach_mode(ism, iov, out_num, in_sg, in_num);

    } else if (ctrl.class == VIRTIO_ISM_CTRL_EVENT_VECTOR) {
        wn = virtio_ism_handle_event_vector(ism, iov, out_num, in_sg, in_num);
    }

    if (wn < 0) {
        status = wn;
        wn = sizeof(status);
    } else {
        wn += sizeof(status);
        status = VIRTIO_ISM_OK;
    }

    iov_from_buf(in_sg, in_num, 0, &status, sizeof(status));

    g_free(iov2);
    return wn;
}

static void virtio_ism_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;

    for (;;) {
        size_t written;
        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        written = virtio_ism_handle_ctrl_iov(vdev, elem->in_sg, elem->in_num,
                                              elem->out_sg, elem->out_num);
        if (written > 0) {
            virtqueue_push(vq, elem, written);
            virtio_notify(vdev, vq);
            g_free(elem);
        } else {
            virtqueue_detach_element(vq, elem, 0);
            g_free(elem);
            break;
        }
    }
}

static void virtio_ism_reset(VirtIODevice *vdev)
{
}

static uint64_t virtio_ism_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    return features;
}

static void virtio_ism_set_features(VirtIODevice *vdev, uint64_t features)
{
}


static void virtio_ism_set_status(struct VirtIODevice *vdev, uint8_t status)
{
}

static void virtio_ism_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtISM *ism = VIRTIO_ISM(dev);

    virtio_init(vdev, VIRTIO_ID_ISM, sizeof(struct virtio_ism_config));

    ism->ctrl_vq = virtio_add_queue(vdev, 64, virtio_ism_handle_ctrl);
    ism->vdev = vdev;

    ism->devid = qatomic_fetch_inc(&devindex);

    devlist[ism->devid] = ism;
}

static void virtio_ism_device_unrealize(DeviceState *dev)
{

}

static uint64_t virtio_ism_pci_common_read(void *opaque, hwaddr addr,
                                           unsigned size)
{
    return 0;
}

static void virtio_ism_pci_common_write(void *opaque, hwaddr addr,
                                        uint64_t val, unsigned size)
{
    static const uint64_t value = 1;
    struct virtio_ism_chunk *c;
    struct VirtISMRegion *r;
    VirtISM *ism = opaque;
    int ret;
    uint64_t pos;

    pos = (uint64_t)addr;

    c = ism->chunks + pos;
    r = c->region;

    if (r->peer_irqfd != -1) {
        ret = write(r->peer_irqfd, &value, sizeof(value));
        if (ret < 0) {
            printf("mmio write %d err: %d errno: %d\n", r->peer_irqfd, ret, errno);
        }
    }
}

static void virtio_ism_instance_init(Object *obj)
{
    VirtISM *ism = VIRTIO_ISM(obj);
    struct virtio_ism_chunk *c;
    uint64_t shm_size;
    uint64_t notify_size;
    int i;

    shm_size = ism->shm_size;

    notify_size = shm_size / ism->chunk_size * 1;
    ism->chunk_num = shm_size / ism->chunk_size;

    device_add_bootindex_property(obj, &ism->bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(ism));

    static const MemoryRegionOps ops = {
        .read = virtio_ism_pci_common_read,
        .write = virtio_ism_pci_common_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };

    ism->shmp = mmap(NULL, shm_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(ism->shmp != MAP_FAILED);

    memory_region_init_io(&ism->notify.mem.mr, OBJECT(ism), &ops, ism, "virtio-ism-notify", notify_size);
    memory_region_init_ram_ptr(&ism->shm.mem.mr, OBJECT(ism), "virtio-ism-shm", shm_size, ism->shmp);

    ism->shm.mem.offset  = 0;
    ism->shm.mem.size    = shm_size;
    ism->shm.mem.type    = VIRTIO_PCI_CAP_SHARED_MEMORY_CFG;
    ism->shm.cap.cap_len = sizeof(struct virtio_pci_cap64);
    ism->shm.cap.id      = VIRTIO_ISM_SHM_ID_REGIONS;

    ism->notify.mem.offset  = shm_size;
    ism->notify.mem.size    = notify_size;
    ism->notify.mem.type    = VIRTIO_PCI_CAP_SHARED_MEMORY_CFG;
    ism->notify.cap.cap_len = sizeof(struct virtio_pci_cap64);
    ism->notify.cap.id      = VIRTIO_ISM_SHM_ID_NOTIFY;

    qht_init(&ism->ht, __region_cmp, 0, QHT_MODE_AUTO_RESIZE);

    ism->chunks = malloc(sizeof(*ism->chunks) * ism->chunk_num);

    QLIST_INIT(&ism->chunk_free);

    for (i = ism->chunk_num - 1; i >= 0; --i) {
        c = ism->chunks + i;
        c->idx = i;
        c->mmaped = false;

        QLIST_INSERT_HEAD(&ism->chunk_free, c, node);
    }

    int size;
    size = sizeof(*ism->notifiers) * 2048;
    ism->notifiers = malloc(size);
    memset(ism->notifiers, 0, size);

    create_server();
}

static bool dev_unplug_pending(void *opaque)
{
    DeviceState *dev = opaque;
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(dev);

    return vdc->primary_unplug_pending(dev);
}


static int virtio_ism_pre_save(void *opaque)
{
    return 0;
}

#define VIRTIO_ISM_VM_VERSION    11

static const VMStateDescription vmstate_virtio_net = {
    .name = "virtio-ism",
    .minimum_version_id = VIRTIO_ISM_VM_VERSION,
    .version_id = VIRTIO_ISM_VM_VERSION,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
    .pre_save = virtio_ism_pre_save,
    .dev_unplug_pending = dev_unplug_pending,
};

static Property virtio_ism_properties[] = {
    DEFINE_PROP_UINT64("shm_size", VirtISM, shm_size, 10 * 1024 * 1024 * 1024),
    DEFINE_PROP_UINT32("chunk_size", VirtISM, chunk_size, 1024 * 1024),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ism_get_config(VirtIODevice *vdev, uint8_t *config)
{
    struct virtio_ism_config cfg = {};
    VirtISM *ism = VIRTIO_ISM(vdev);

    virtio_stl_p(vdev, &cfg.gid, 0); // TODO
    virtio_stl_p(vdev, &cfg.devid, 0); // TODO
    virtio_stl_p(vdev, &cfg.chunk_size, ism->chunk_size);
    virtio_stl_p(vdev, &cfg.notify_size, 1);

    memcpy(config, &cfg, sizeof(cfg));
}

static void virtio_ism_set_config(VirtIODevice *vdev, const uint8_t *config)
{

}

static void virtio_ism_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_ism_properties);
    dc->vmsd = &vmstate_virtio_net;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    vdc->realize      = virtio_ism_device_realize;
    vdc->unrealize    = virtio_ism_device_unrealize;
    vdc->reset        = virtio_ism_reset;
    vdc->set_status   = virtio_ism_set_status;
    vdc->get_features = virtio_ism_get_features;
    vdc->set_features = virtio_ism_set_features;
    vdc->get_config   = virtio_ism_get_config;
    vdc->set_config   = virtio_ism_set_config;
    vdc->set_status   = virtio_ism_set_status;
}

static const TypeInfo virtio_ism_info = {
    .name          = TYPE_VIRTIO_ISM,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtISM),
    .instance_init = virtio_ism_instance_init,
    .class_init    = virtio_ism_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_ism_info);
}

type_init(virtio_register_types)
