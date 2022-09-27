/*
 * Virtio ISM PCI Bindings
 *
 * Copyright (c) 2021 Alibaba Group.
 *
 * Authors:  Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 *
 */

#include "qemu/osdep.h"

#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-ism.h"
#include "hw/virtio/virtio-pci.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"

#include "standard-headers/linux/virtio_pci.h"

typedef struct VirtIOISMPCI VirtIOISMPCI;

/*
 * virtio-ism-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_ISM_PCI "virtio-ism-pci-base"
DECLARE_INSTANCE_CHECKER(VirtIOISMPCI, VIRTIO_ISM_PCI,
                         TYPE_VIRTIO_ISM_PCI)

struct VirtIOISMPCI {
    VirtIOPCIProxy parent_obj;
    VirtISM vdev;
};

static void virtio_ism_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOISMPCI *dev = VIRTIO_ISM_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtISM *ism = VIRTIO_ISM(vdev);

    vpci_dev->custom_mem_n = 2;
    vpci_dev->custom_mem = ism->mem;

    vpci_dev->nvectors = ism->region_num;
    vpci_dev->nvectors += 1; /* Config interrupt */
    vpci_dev->nvectors += 1; /* Control vq */

    ism->vpci_dev = vpci_dev;

    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static Property virtio_ism_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ism_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    VirtioPCIClass *vpciklass = VIRTIO_PCI_CLASS(klass);

    k->romfile = "efi-virtio.rom";
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->device_id = PCI_DEVICE_ID_VIRTIO_ISM;
    k->revision = VIRTIO_PCI_ABI_VERSION;
    k->class_id = PCI_CLASS_MEMORY_OTHER;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_ism_properties);
    vpciklass->realize = virtio_ism_pci_realize;
}

static void virtio_ism_pci_instance_init(Object *obj)
{
    VirtIOISMPCI *dev = VIRTIO_ISM_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_ISM);

    object_property_add_alias(obj, "bootindex", OBJECT(&dev->vdev),
                              "bootindex");
}

static const VirtioPCIDeviceTypeInfo virtio_ism_pci_info = {
    .base_name             = TYPE_VIRTIO_ISM_PCI,
    .generic_name          = "virtio-ism-pci",
    .transitional_name     = "virtio-ism-pci-transitional",
    .non_transitional_name = "virtio-ism-pci-non-transitional",
    .instance_size = sizeof(VirtIOISMPCI),
    .instance_init = virtio_ism_pci_instance_init,
    .class_init    = virtio_ism_pci_class_init,
};

static void virtio_ism_pci_register(void)
{
    virtio_pci_types_register(&virtio_ism_pci_info);
}

type_init(virtio_ism_pci_register)
