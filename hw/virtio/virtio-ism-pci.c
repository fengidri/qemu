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
#include "sysemu/kvm.h"
#include "hw/pci/msix.h"

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

static int ism_vector_unmask(PCIDevice *dev, unsigned vector,
                                 MSIMessage msg)
{
    VirtIOPCIProxy *vpci_dev = container_of(dev, VirtIOPCIProxy, pci_dev);
    DeviceState *vdev = DEVICE(&VIRTIO_ISM_PCI(vpci_dev)->vdev);
    VirtISM *ism = VIRTIO_ISM(vdev);
    struct virtio_ism_notifier *notifier;
    int ret;

    notifier = ism->notifiers + vector;
    if (!notifier->done)
        return 0;

    ret = kvm_irqchip_update_msi_route(kvm_state, notifier->vector_irqfd.virq, msg, dev);
    if (ret < 0) {
        return ret;
    }
    kvm_irqchip_commit_routes(kvm_state);

    ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, &notifier->notifier, NULL, notifier->vector_irqfd.virq);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static void ism_vector_mask(PCIDevice *dev, unsigned vector)
{
    VirtIOPCIProxy *vpci_dev = container_of(dev, VirtIOPCIProxy, pci_dev);
    DeviceState *vdev = DEVICE(&VIRTIO_ISM_PCI(vpci_dev)->vdev);
    VirtISM *ism = VIRTIO_ISM(vdev);
    struct virtio_ism_notifier *notifier;
    int ret;

    notifier = ism->notifiers + vector;
    if (!notifier->done)
        return;

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state,  &notifier->notifier, notifier->vector_irqfd.virq);
    if (ret < 0) {
        return;
    }
}

static void ism_vector_poll(PCIDevice *dev,
                                unsigned int vector_start,
                                unsigned int vector_end)
{
    VirtIOPCIProxy *vpci_dev = container_of(dev, VirtIOPCIProxy, pci_dev);
    DeviceState *vdev = DEVICE(&VIRTIO_ISM_PCI(vpci_dev)->vdev);
    VirtISM *ism = VIRTIO_ISM(vdev);
    struct virtio_ism_notifier *notifier;
    unsigned int vector;

    for (vector = vector_start; vector < vector_end; vector++) {
        notifier = ism->notifiers + vector;
        if (!notifier->done)
            continue;

        if (!msix_is_masked(dev, vector)) {
            continue;
        }

        if (event_notifier_test_and_clear(&notifier->notifier)) {
            msix_set_pending(dev, vector);
        }
    }
}
static void virtio_ism_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOISMPCI *dev = VIRTIO_ISM_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtISM *ism = VIRTIO_ISM(vdev);

    vpci_dev->custom_mem_n = 2;
    vpci_dev->custom_mem = ism->mem;

    vpci_dev->nvectors = ism->chunk_num;
    vpci_dev->nvectors += 1; /* Config interrupt */
    vpci_dev->nvectors += 1; /* Control vq */

    if (vpci_dev->nvectors > 2048)
        vpci_dev->nvectors = 2048;

    ism->vpci_dev = vpci_dev;



    if (msix_set_vector_notifiers(&vpci_dev->pci_dev,
                                  ism_vector_unmask,
                                  ism_vector_mask,
                                  ism_vector_poll)) {
        error_report("ism: msix_set_vector_notifiers failed");
    }

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
