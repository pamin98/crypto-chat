/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
    DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type;
    int *host_fd, *ret;
    unsigned int *ioctl_cmd;

    DEBUG_IN();

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    } 

    DEBUG("I have got an item from VQ :)");

    syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");
        host_fd = elem->in_sg[0].iov_base;
        *host_fd = open("/dev/crypto", O_RDWR);
        if(*host_fd < 0){
            DEBUG("Unable to open /dev/crypto");
            perror("open");
            return;
        }
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        host_fd = elem->out_sg[1].iov_base;
        if(close(*host_fd) < 0){
            DEBUG("Unable to close file.");
            perror("close");
            return;
        }
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        host_fd = elem->out_sg[1].iov_base;
        ioctl_cmd = elem->out_sg[2].iov_base;
        switch(*ioctl_cmd){
        case CIOCGSESSION:
            DEBUG("CIOCGSESSION");
            unsigned char * session_key = elem->out_sg[3].iov_base;
            struct session_op * sess = elem->in_sg[0].iov_base;
            ret = elem->in_sg[1].iov_base;
            sess->key = session_key;
            if(ioctl(*host_fd, CIOCGSESSION, sess)){
                DEBUG("Error in CIOCGSESSION")
                perror("ioctl");
                *ret = -1;
            }
            else
                *ret = 0;
            break;
        case CIOCFSESSION:
            DEBUG("CIOCFSESSION");
            uint32_t *ses_id = elem->out_sg[3].iov_base;
            ret = elem->in_sg[0].iov_base;
            if(ioctl(*host_fd, CIOCFSESSION, ses_id)){
                DEBUG("Error in CIOCFSESSION");
                perror("ioctl");
                *ret = -1;
            }
            else
                *ret = 0;
            break;
        case CIOCCRYPT:
            DEBUG("CIOCCRYPT");
            struct crypt_op * crypt_operations = elem->out_sg[3].iov_base;
            unsigned char * src = elem->out_sg[4].iov_base;
            unsigned char * iv = elem->out_sg[5].iov_base;
            unsigned char * dst = elem->in_sg[0].iov_base;
            ret = elem->in_sg[1].iov_base;
            crypt_operations->src = src;
            crypt_operations->iv = iv;
            crypt_operations->dst = dst;
            if(ioctl(*host_fd, CIOCCRYPT, crypt_operations)){
                DEBUG("Error in CIOCCRYPT");
                perror("ioctl");
                *ret = -1;
            }
            else 
                *ret = 0;
            break;
        default:
            DEBUG("No such ioctl command");
            break;
        }
        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }

    virtqueue_push(vq, elem, 0);
    virtio_notify(vdev, vq);
    g_free(elem);
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
