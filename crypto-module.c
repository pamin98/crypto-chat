#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

struct crypto_driver_data crdrvdata;

static void vq_has_data(struct virtqueue *vq)
{
	debug("Entering");
	debug("Leaving");
}

static struct virtqueue *find_vq(struct virtio_device *vdev)
{
	int err;
	struct virtqueue *vq;

	debug("Entering");

	vq = virtio_find_single_vq(vdev, vq_has_data, "crypto-vq");
	if (IS_ERR(vq)) {
		debug("Could not find vq");
		vq = NULL;
	}

	debug("Leaving");

	return vq;
}

/**
 * This function is called each time the kernel finds a virtio device
 * that we are associated with.
 */
static int virtcons_probe(struct virtio_device *vdev)
{
	int ret = 0;
	struct crypto_device *crdev;

	debug("Entering");

	crdev = kzalloc(sizeof(*crdev), GFP_KERNEL);
	if (!crdev) {
		ret = -ENOMEM;
		goto out;
	}

	crdev->vdev = vdev;
	vdev->priv = crdev;

	crdev->vq = find_vq(vdev);
	if (!(crdev->vq)) {
		ret = -ENXIO;
		goto out;		
	}

	/* Other initializations. */
	/* Initialize the spinlock */
	spin_lock_init(&crdev->lock);

	/**
	 * Grab the next minor number and put the device in the driver's list. 
	 **/
	spin_lock_irq(&crdrvdata.lock);
	crdev->minor = crdrvdata.next_minor++;
	list_add_tail(&crdev->list, &crdrvdata.devs);
	spin_unlock_irq(&crdrvdata.lock);
	debug("Got minor = %u", crdev->minor);

	debug("Leaving");

out:
	return ret;
}

static void virtcons_remove(struct virtio_device *vdev)
{
	struct crypto_device *crdev = vdev->priv;

	debug("Entering");

	/* Delete virtio device list entry. */
	spin_lock_irq(&crdrvdata.lock);
	list_del(&crdev->list);
	spin_unlock_irq(&crdrvdata.lock);

	/* NEVER forget to reset virtio device and delete device virtqueues. */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	kfree(crdev);

	debug("Leaving");
}

static struct virtio_device_id id_table[] = {
	{VIRTIO_ID_CRYPTODEV, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	0
};

static struct virtio_driver virtio_crypto = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtcons_probe,
	.remove =	virtcons_remove,
};

/**
 * The function that is called when our module is being inserted in
 * the running kernel.
 **/
static int __init init(void)
{
	int ret = 0;
	debug("Entering");

	/* Register the character devices that we will use. */
	ret = crypto_chrdev_init();
	if (ret < 0) {
		printk(KERN_ALERT "Could not initialize character devices.\n");
		goto out;
	}

	INIT_LIST_HEAD(&crdrvdata.devs);
	spin_lock_init(&crdrvdata.lock);

	/* Register the virtio driver. */
	ret = register_virtio_driver(&virtio_crypto);
	if (ret < 0) {
		printk(KERN_ALERT "Failed to register virtio driver.\n");
		goto out_with_chrdev;
	}

	debug("Leaving");
	return ret;

out_with_chrdev:
	debug("Leaving");
	crypto_chrdev_destroy();
out:
	return ret;
}

/**
 * The function that is called when our module is being removed.
 * Make sure to cleanup everything.
 **/
static void __exit fini(void)
{
	debug("Entering");
	crypto_chrdev_destroy();
	unregister_virtio_driver(&virtio_crypto);
	debug("Leaving");
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio crypto driver");
MODULE_LICENSE("GPL");
