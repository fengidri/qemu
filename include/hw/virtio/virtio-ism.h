/*
 * Virtio ISM PCI Bindings
 *
 * Copyright (c) 2021 Alibaba Group.
 *
 * Authors:  Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 *
 */

#ifndef QEMU_VIRTIO_ISM_H
#define QEMU_VIRTIO_ISM_H

#include "qemu/qht.h"
#include "qemu/units.h"
//#include "standard-headers/linux/virtio_ism.h"
#include "hw/virtio/virtio.h"
#include "net/announce.h"
#include "qemu/option_int.h"
#include "qom/object.h"

#include "chardev/char-fe.h"

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "sysemu/numa.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-access.h"

#include "standard-headers/linux/virtio_pci.h"


#define TYPE_VIRTIO_ISM "virtio-ism-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtISM, VIRTIO_ISM)

struct virtio_ism_config {
	__virtio64 gid;
	__virtio64 devid;
	__virtio64 chunk_size;
	__virtio64 notify_size;
};

#define   VIRTIO_ISM_EVENT_UPDATE (1 << 0)
#define   VIRTIO_ISM_EVENT_ATTACH (1 << 1)
#define   VIRTIO_ISM_EVENT_DETACH (1 << 2)

struct virtio_ism_event_update {
	__virtio64 ev_type;
	__virtio64 offset;
	__virtio64 devid;
};

struct virtio_ism_event_attach_detach {
	__virtio64 ev_type;
	__virtio64 offset;
	__virtio64 devid;
	__virtio64 peers;
};

enum virtio_ism_shm_id {
	VIRTIO_ISM_SHM_ID_UNDEFINED = 0,
	VIRTIO_ISM_SHM_ID_REGIONS   = 1,
	VIRTIO_ISM_SHM_ID_NOTIFY    = 2,
};

/* ack values */
#define VIRTIO_ISM_OK      0
#define VIRTIO_ISM_ERR     255

#define VIRTIO_ISM_ENOENT  2
#define VIRTIO_ISM_E2BIG   7
#define VIRTIO_ISM_ENOMEM  12
#define VIRTIO_ISM_ENOSPEC 28

#define VIRTIO_ISM_PERM_EATTACH 100
#define VIRTIO_ISM_PERM_EREAD   101
#define VIRTIO_ISM_PERM_EWRITE  102

struct virtio_ism_ctrl_alloc {
	__virtio64 size;
};

struct virtio_ism_area {
	__virtio64 offset;
	__virtio64 size;
};

struct virtio_ism_ctrl_alloc_reply {
	__virtio64 token;
	__virtio64 num;
	struct virtio_ism_area area[];
};

#define VIRTIO_ISM_CTRL_ALLOC  0
	#define VIRTIO_ISM_CTRL_ALLOC_REGION 0

struct virtio_ism_ctrl_attach {
	__virtio64 token;
	__virtio32 rw_perm;
};

struct virtio_ism_ctrl_attach_reply {
	__virtio64 num;
	struct virtio_ism_area area[];
};


#define VIRTIO_ISM_CTRL_ATTACH  1
	#define VIRTIO_ISM_CTRL_ATTACH_REGION 0

struct virtio_ism_ctrl_detach {
	__virtio64 token;
};

#define VIRTIO_ISM_CTRL_DETACH  2
	#define VIRTIO_ISM_CTRL_DETACH_REGION 0


struct virtio_ism_ctrl_grant_default {
	__virtio64 token;
	__virtio64 permissions;
};

struct virtio_ism_ctrl_grant {
	__virtio64 token;
	__virtio64 permissions;
	__virtio64 peer_devid;
};

#define VIRTIO_ISM_CTRL_GRANT  3
	#define VIRTIO_ISM_CTRL_GRANT_SET_DEFAULT    0
	#define VIRTIO_ISM_CTRL_GRANT_SET_FOR_DEVICE 1

#define VIRTIO_ISM_PERM_READ       (1 << 0)
#define VIRTIO_ISM_PERM_WRITE      (1 << 1)

#define VIRTIO_ISM_PERM_ATTACH     (1 << 2)

#define VIRTIO_ISM_PERM_MANAGE     (1 << 3)
#define VIRTIO_ISM_PERM_CLEAN_DEFAULT     (1 << 4)


struct virtio_ism_ctrl_irq_vector {
	__virtio64 token;
	__virtio64 vector;
};

#define VIRTIO_ISM_CTRL_EVENT_VECTOR  4
	#define VIRTIO_ISM_CTRL_EVENT_VECTOR_SET 0


struct virtio_ism_notifier {
    bool          done;
    EventNotifier notifier;
    VirtIOIRQFD   vector_irqfd;
    int refs;
};

struct virtio_ism_chunk {
    uint64_t      idx;
    bool mmaped;
    struct VirtISMRegion *region;
    QLIST_ENTRY(virtio_ism_chunk) node;
};

struct VirtISMRegion {
    struct virtio_ism_notifier *notifier;

    int           peer_irqfd;

    uint64_t      token;
    bool          creator;

    int           chunks_n;

    QLIST_HEAD(, virtio_ism_chunk) chunks;
};

typedef struct VirtISM {
    VirtIODevice parent_obj;

    unsigned char devid;

    int32_t bootindex;

    uint64_t shm_size;
    uint64_t chunk_num;
    uint32_t chunk_size;

    VirtIODevice *vdev;
    VirtIOPCIProxy *vpci_dev;

    VirtQueue *ctrl_vq;

    union {
        struct {
            struct VirtIOPCICustomMem shm;
            struct VirtIOPCICustomMem notify;
        };
        struct VirtIOPCICustomMem mem[2];
    };

    struct virtio_ism_chunk *chunks;
    struct virtio_ism_notifier *notifiers;

    struct qht ht;
    void *shmp;

    QLIST_HEAD(, virtio_ism_chunk) chunk_free;

} VirtISM;

struct virtio_ism_ctrl_hdr {
	uint8_t class;
	uint8_t cmd;
} QEMU_PACKED;


struct control_buf {
	struct virtio_ism_ctrl_hdr hdr;
	unsigned char status;
};

#endif


