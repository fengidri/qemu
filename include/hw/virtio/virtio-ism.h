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


#define VIRTIO_ISM_F_EVENT_IRQ 0

enum virtio_ism_shm_id {
        VIRTIO_ISM_SHM_ID_UNDEFINED = 0,
        VIRTIO_ISM_SHM_ID_REGIONS   = 1,
        VIRTIO_ISM_SHM_ID_NOTIFY    = 2,
};

struct virtio_ism_ctrl_alloc {
       uint64_t size;
};

struct virtio_ism_ctrl_alloc_reply {
       uint64_t token;
       uint64_t offset;
};

#define VIRTIO_ISM_CTRL_ALLOC  0
 #define VIRTIO_ISM_CTRL_ALLOC_REGION 0

struct virtio_ism_ctrl_attach {
       uint64_t token;
};

struct virtio_ism_ctrl_attach_reply {
       uint64_t offset;
};

#define VIRTIO_ISM_CTRL_ATTACH  1
 #define VIRTIO_ISM_CTRL_ATTACH_REGION 0

struct virtio_ism_ctrl_grant {
	uint64_t offset;
	uint64_t peer_devid;
	uint64_t permissions;
};

struct virtio_ism_ctrl_detach {
	uint64_t offset;
};

#define VIRTIO_ISM_CTRL_DETACH  2
	#define VIRTIO_ISM_CTRL_DETACH_REGION 0

#define VIRTIO_ISM_CTRL_GRANT  3
	#define VIRTIO_ISM_CTRL_GRANT_SET 0

#define VIRTIO_ISM_PERM_READ       (1 << 0)
#define VIRTIO_ISM_PERM_WRITE      (1 << 1)
#define VIRTIO_ISM_PERM_ATTACH     (1 << 2)
#define VIRTIO_ISM_PERM_MANAGE     (1 << 3)
#define VIRTIO_ISM_PERM_DENY_OTHER (1 << 4)

struct virtio_ism_ctrl_irq_vector {
       uint64_t offset;
       uint64_t vector;
};

#define VIRTIO_ISM_CTRL_DETACH  2
 #define VIRTIO_ISM_CTRL_DETACH_REGION 0

#define VIRTIO_ISM_CTRL_GRANENT  3
 #define VIRTIO_ISM_CTRL_GRANENT_PEERID 0

#define VIRTIO_ISM_CTRL_EVENT_VECTOR  4
 #define VIRTIO_ISM_CTRL_EVENT_VECTOR_SET 0


struct virtio_ism_config {
	uint64_t gid;
	uint64_t devid;
	uint64_t region_size;
	uint64_t notify_size;
} QEMU_PACKED;

struct VirtISMRegion {
    MemoryRegion  region_mr;

    bool          notifier_done;
    EventNotifier notifier;
    VirtIOIRQFD   vector_irqfd;

    int           peer_irqfd;

    uint64_t      token;
    bool          creator;
};

typedef struct VirtISM {
    VirtIODevice parent_obj;

    int32_t bootindex;

    uint64_t shm_size;
    uint64_t region_num;
    uint32_t region_size;
    uint32_t vector_start;

    uint64_t pos;

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

    struct VirtISMRegion *regions;

} VirtISM;

struct virtio_ism_ctrl_hdr {
	uint8_t class;
	uint8_t cmd;
} QEMU_PACKED;


struct control_buf {
	struct virtio_ism_ctrl_hdr hdr;
	unsigned char status;
};

#define VIRTIO_ISM_ERR -1
#define VIRTIO_ISM_OK 0

#endif


