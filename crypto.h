#ifndef _CRYPTO_H
#define _CRYPTO_H

#define VIRTIO_CRYPTODEV_BLOCK_SIZE    16

#define VIRTIO_CRYPTODEV_SYSCALL_OPEN  0
#define VIRTIO_CRYPTODEV_SYSCALL_CLOSE 1
#define VIRTIO_CRYPTODEV_SYSCALL_IOCTL 2

/* The Virtio ID for virtio crypto ports */
#define VIRTIO_ID_CRYPTODEV            30

/**
 * Global driver data.
 **/
struct crypto_driver_data {
	/* The list of the devices we are handling. */
	struct list_head devs;

	/* The minor number that we give to the next device. */
	unsigned int next_minor;

	spinlock_t lock;
};
extern struct crypto_driver_data crdrvdata;


/**
 * Device info.
 **/
struct crypto_device {
	/* Next crypto device in the list, head is in the crdrvdata struct */
	struct list_head list;

	/* The virtio device we are associated with. */
	struct virtio_device *vdev;

	struct virtqueue *vq;
	
	/* Lock */
	spinlock_t lock;

	/* The minor number of the device. */
	unsigned int minor;
};


/**
 *  Crypto open file.
 **/
struct crypto_open_file {
	/* The crypto device this open file is associated with. */
	struct crypto_device *crdev;

	/* The fd that this device has on the Host. */
	int host_fd;
};

#endif
