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

static int sendfd(int unix_fd, int target_fd, char *buf, int size)
{
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = { NULL, };
    struct iovec    iov[1];
    struct cmsghdr *cmsg;

    memset(control, 0, CMSG_SPACE(sizeof(int)));

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    iov[0].iov_base = buf;
    iov[0].iov_len = size;

    *CMSG_DATA(cmsg) = target_fd;

    return sendmsg(unix_fd, &msg, 0);
}

static int recvfd(int unix_fd, int *target_fd, char *buf, int size)
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

    iov[0].iov_base = buf;
    iov[0].iov_len = size;

    ret = recvmsg(unix_fd, &msg, 0);
    if (ret < 0)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

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
    VirtISM *ism;
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
    int fd;
    int err, ret;
    int irqfd;
    char pos[10];
    struct VirtISMRegion *r;
    int index;
    VirtISM *ism = s->ism;

    fd = accept(s->fd.fd, NULL, NULL);

    ret = recvfd(fd, &irqfd, pos, sizeof(pos));
    if (ret < 0) {
        close(fd);
        return ret;
    }

    index = atoi(pos);

    printf("recv from unix socket: %s %d recv irqfd: %d\n", pos, index, irqfd);

    r = ism->regions + index;
    r->peer_irqfd = irqfd;

    err = sendfd(fd, event_notifier_get_wfd(&r->notifier), pos, strlen(pos));
    if (err)
        return err;

    close(fd);

    return TRUE;
}

static int create_server(VirtISM *ism)
{
    char buf[512];
    Error *err;
    int sock;
    Error *error_abort;
    IOThread *ism_iothread;
    GSource *source;
    GSourceServer *s;
    struct stat st;

    if (stat("/dev/shm/virtio-ism", &st) || !S_ISDIR(st.st_mode)) {
        if (mkdir("/dev/shm/virtio-ism", S_IRWXU)) {
            printf("create /dev/shm/virtio-ism fail\n");
            return -1;
        }
    }

    snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/server-%d", getpid());

    sock = unix_listen(buf, &err);
    if (!sock) {
        printf("create unix socket fail. check for %s\n", buf);
        assert(sock);
    }

    ism_iothread = iothread_create("ism_iothread", &error_abort);
    assert(ism_iothread);

    source = g_source_new(&g_s_funcs, sizeof(GSourceServer));
    s = (GSourceServer *) source;

    s->ism = ism;
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

static int kvm_virtio_pci_vq_vector_use(VirtIOPCIProxy *proxy,
                                        unsigned int vector, VirtIOIRQFD *irqfd)
{
    int ret;

    if (irqfd->users == 0) {
        KVMRouteChange c = kvm_irqchip_begin_route_changes(kvm_state);
        ret = kvm_irqchip_add_msi_route(&c, vector, &proxy->pci_dev);
        if (ret < 0) {
            return ret;
        }
        kvm_irqchip_commit_route_changes(&c);
        irqfd->virq = ret;
    }
    irqfd->users++;
    return 0;
}

static int irqfd_init(VirtISM *ism, struct VirtISMRegion *r, int vector)
{
    VirtIOPCIProxy *vpci_dev;
    int err1, err2;

    vpci_dev = ism->vpci_dev;

    err1 = event_notifier_init(&r->notifier, 0);
    if (err1 < 0) {
        return err1;
    }

    event_notifier_set_handler(&r->notifier, NULL);

    err1 = kvm_virtio_pci_vq_vector_use(vpci_dev, vector, &r->vector_irqfd);

    err2 = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, &r->notifier, NULL, r->vector_irqfd.virq);

    printf("init irqfd: %d %d irqfd: %d\n", err1, err2, event_notifier_get_wfd(&r->notifier));

    return 0;

}

static int virtio_ism_init_notifier(VirtISM *ism, struct VirtISMRegion *r, int vector)
{
    int err;

    if (r->notifier_done)
        return 0;

    err = irqfd_init(ism, r, vector);
    if (err)
        return err;

    r->notifier_done = true;

    return 0;
}

static uint64_t make_token(int pos)
{
    uint64_t token;
    uint64_t pid;

    pid = getpid();

    token = pid << 32;
    token += pos;

    return token;
}


static void parse_token(uint64_t token, int *pid, uint32_t *pos)
{
    *pid = token >> 32;
    *pos = (token << 32) >> 32;
}

static int map_region(VirtISM *ism, uint64_t token, bool create)
{
    struct VirtISMRegion *r;
    char buf[512];
    int64_t offset;
    int fd;
    MemoryRegion *mr;
    Error *err;

    snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/shm-%lu", token);

    if (create) {
        fd = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1)
            return -1;

        if (ftruncate(fd, ism->region_size))
            return -1;
    } else {
        fd = open(buf, O_RDWR);
        if (fd == -1)
            return -1;
    }

    r = ism->regions + ism->pos;
    mr = &r->region_mr;

    offset = ism->pos * ism->region_size;

    memory_region_init_ram_from_fd(mr, OBJECT(ism),
                                   "virtio-ism-region",
                                   ism->region_size,
                                   RAM_SHARED, fd, 0, &err);

    memory_region_add_subregion(&ism->shm.mem.mr, offset, mr);

    ism->pos++;

    return offset;

}

static int virtio_ism_attach_peer(VirtISM *ism, struct VirtISMRegion *r)
{
    char buf[512];
    char buf_pos[10];
    uint32_t pos;
    int pid, buf_len;
    int ret;
    Error *e;
    int sock;

    if (r->creator)
        return 0;

    parse_token(r->token, &pid, &pos);

    snprintf(buf_pos, sizeof(buf_pos), "%d", pos);

    buf_len = snprintf(buf, sizeof(buf), "/dev/shm/virtio-ism/server-%d", pid);

    sock = unix_connect(buf, &e);
    if (sock < 0)
        return sock;

    ret = sendfd(sock, event_notifier_get_wfd(&r->notifier), buf_pos, buf_len);
    if (ret < 0)
        return ret;

    ret = recvfd(sock, &r->peer_irqfd, buf_pos, sizeof(buf_pos));
    if (ret < 0)
        return ret;

    return 0;
}

static int virtio_ism_handle_event_vector(VirtISM *ism,
                                          const struct iovec *out_iov, unsigned out_num,
                                          const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_irq_vector iv;
    struct VirtISMRegion *r;
    int err;

    iov_to_buf(out_iov, out_num, 0, &iv, sizeof(iv));

    r = ism->regions + (virtio_ldq_p(ism->vdev, &iv.offset) / ism->region_size);

    virtio_ism_init_notifier(ism, r, virtio_ldq_p(ism->vdev, &iv.vector));

    err = virtio_ism_attach_peer(ism, r);
    if (err)
        return err;

    printf("map irq vector %lu to offset: %lu\n", iv.vector, iv.offset);

    return 0;
}

static int virtio_ism_handle_alloc_mode(VirtISM *ism,
                                         const struct iovec *out_iov, unsigned out_num,
                                         const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_alloc_reply alloc;
    int64_t offset;
    struct VirtISMRegion *r;
    uint64_t token;

    r = ism->regions + ism->pos;
    printf("alloc pos: %lu\n", ism->pos);

    token = make_token(ism->pos);

    offset = map_region(ism, token, true);
    if (offset < 0)
        return offset;

    r->token = token;
    r->creator = true;

    virtio_stq_p(ism->vdev, &alloc.offset, offset);
    virtio_stq_p(ism->vdev, &alloc.token, token);

    iov_from_buf(in_iov, in_num, sizeof(unsigned char), &alloc, sizeof(alloc));

    printf("map shm to mr in sg: %d %lu %lu\n", in_num, in_iov[0].iov_len, in_iov[1].iov_len);

    return sizeof(alloc);
}

static int virtio_ism_handle_attach_mode(VirtISM *ism,
                                          const struct iovec *out_iov, unsigned out_num,
                                          const struct iovec *in_iov, unsigned in_num)
{
    struct virtio_ism_ctrl_attach out;
    struct virtio_ism_ctrl_attach_reply in;
    struct VirtISMRegion *r;
    int64_t offset;
    uint64_t token;

    iov_to_buf(out_iov, out_num, 0, &out, sizeof(out));

    r = ism->regions + ism->pos;
    printf("attach pos: %lu\n", ism->pos);

    token = virtio_ldq_p(ism->vdev, &out.token);

    offset = map_region(ism, token, false);
    printf("attach offset: %lu\n", offset);
    if (offset < 0)
        return offset;

    virtio_stq_p(ism->vdev, &in.offset, offset);

    iov_from_buf(in_iov, in_num, sizeof(unsigned char), &in, sizeof(in));

    r->token = token;


    return sizeof(out);
}

static int virtio_ism_handle_dettach_mode(VirtISM *ism,
                                           const struct iovec *out_iov, unsigned out_num,
                                           const struct iovec *in_iov, unsigned in_num)
{
    printf("dettach\n");

    return 0;
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
        wn = virtio_ism_handle_dettach_mode(ism, iov, out_num, in_sg, in_num);

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

    create_server(ism);
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
    VirtISM *ism = opaque;
    struct VirtISMRegion *r;
    int ret;
    uint64_t pos;

    pos = (uint64_t)addr;

    r = ism->regions + pos;

    if (r->peer_irqfd != -1) {
        ret = write(r->peer_irqfd, &value, sizeof(value));
        if (ret < 0) {
            //TODO
        }
    }
}

static void virtio_ism_instance_init(Object *obj)
{
    VirtISM *ism = VIRTIO_ISM(obj);
    struct VirtISMRegion *r;
    uint64_t shm_size;
    uint64_t notify_size;
    int i;

    shm_size = ism->shm_size;

    notify_size = shm_size / ism->region_size;
    ism->region_num = shm_size / ism->region_size;
    ism->vector_start = 10;

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

    memory_region_init_io(&ism->notify.mem.mr, OBJECT(ism), &ops, ism, "virtio-ism-notify", notify_size);
    memory_region_init(&ism->shm.mem.mr, OBJECT(ism), "virtio-ism-shm", shm_size);

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

    ism->regions = malloc(sizeof(*ism->regions) * ism->region_num);

    for (i = 0; i < ism->region_num; ++i) {
        r = ism->regions + i;
        memset(r, 0, sizeof(*r));
        r->peer_irqfd = -1;
    }
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
    DEFINE_PROP_UINT64("shm_size", VirtISM, shm_size, 1024 * 1024 * 1024),
    DEFINE_PROP_UINT32("region_size", VirtISM, region_size, 1024 * 1024),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ism_get_config(VirtIODevice *vdev, uint8_t *config)
{
    struct virtio_ism_config cfg = {};
    VirtISM *ism = VIRTIO_ISM(vdev);

    virtio_stl_p(vdev, &cfg.gid, 0); // TODO
    virtio_stl_p(vdev, &cfg.devid, 0); // TODO
    virtio_stl_p(vdev, &cfg.region_size, ism->region_size);

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
//    vdc->vmsd                   = &vmstate_virtio_net_device;
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
