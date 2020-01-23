/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	unsigned long flags;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist *sg[2], syscall_type_sg, host_fd_sg;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg[0] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sg[1] = &host_fd_sg;

	/* Add the buffers to the virtqueue for the host to process */
	spin_lock_irqsave(&crdev->lock, flags);
	if((ret = virtqueue_add_sgs(crdev->vq, sg, 1, 1, &syscall_type_sg, GFP_ATOMIC)) < 0){
		debug("Could not add buffers to the virtqueue.");
		spin_unlock_irqrestore(&crdev->lock, flags);
		goto fail;
	}
	/* Alert the host that data has been added to the virtqueue */
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while(!virtqueue_get_buf(crdev->vq, &len));
	spin_unlock_irqrestore(&crdev->lock, flags);

	/* If host failed to open() return -ENODEV. */
	if(*host_fd < 0){
		debug("Host failed to open(), returning -ENODEV");
		ret = -ENODEV;
		goto fail;
	}
	crof->host_fd = *host_fd;		

fail:
	debug("Leaving");
	kfree(host_fd);
	kfree(syscall_type);
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	unsigned long flags;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int len, *syscall_type;
	struct scatterlist *sg[2], syscall_type_sg, host_fd_sg;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg[0] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sg[1] = &host_fd_sg;

	spin_lock_irqsave(&crdev->lock, flags);
	if((ret = virtqueue_add_sgs(crdev->vq, sg, 2, 0, &syscall_type_sg, GFP_ATOMIC)) < 0){
		debug("Could not add buffers to the virtqueue.");
		spin_unlock_irqrestore(&crdev->lock, flags);
		goto fail;
	}
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while(!virtqueue_get_buf(crdev->vq, &len));
	spin_unlock_irqrestore(&crdev->lock, flags);
	kfree(crof);

fail:
	kfree(syscall_type);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct session_op *sess;
	struct crypt_op *crypt_operations;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg, session_op_sg, session_key_sg,
					   host_ret_sg, ses_id_sg, crypt_op_sg, src_sg, dst_sg, iv_sg, *sgs[8];
	unsigned int num_out, num_in, len;
	unsigned int *cmd_ptr;
	unsigned int *syscall_type;
	unsigned char *key, *src, *dst, *iv;
	int *host_ret;
	uint32_t *ses_id;
	unsigned long flags;
	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	cmd_ptr = kzalloc(sizeof(*cmd_ptr), GFP_KERNEL);
	host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	src = NULL;
	dst = NULL;
	iv = NULL;
	ses_id = NULL;
	key = NULL;
	crypt_operations = NULL;
	sess = NULL;
	num_out = 0;
	num_in = 0;
	*cmd_ptr = cmd;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&ioctl_cmd_sg, cmd_ptr, sizeof(*cmd_ptr));
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
		if(!sess){
			debug("Can't allocate memory for sess");
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(sess, (struct session_op *) arg, sizeof(struct session_op))){
			debug("copy_from_user");
			kfree(sess);
			ret = -EFAULT;
			goto fail;
		}
		key = kzalloc(sess->keylen * sizeof(unsigned char), GFP_KERNEL);
		if(!key){
			debug("Can't allocate memory for key");
			kfree(sess);
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(key, sess->key, sess->keylen * sizeof(unsigned char))){
			debug("Can't copy key.");
			kfree(sess);
			kfree(key);
			ret = -EFAULT;
			goto fail;
		}
		sg_init_one(&session_key_sg, key, sizeof(*key));
		sgs[num_out++] = &session_key_sg;
		sg_init_one(&session_op_sg, sess, sizeof(*sess));
		sgs[num_out + num_in++] = &session_op_sg;
		sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
		sgs[num_out + num_in++] = &host_ret_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		ses_id = kzalloc(sizeof(uint32_t), GFP_KERNEL);
		if(!ses_id){
			debug("Can't allocate memory for ses_id");
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(ses_id, (uint32_t *) arg, sizeof(uint32_t))){
			debug("copy_from_user");
			kfree(ses_id);
			ret = -EFAULT;
			goto fail;
		}
		sg_init_one(&ses_id_sg, ses_id, sizeof(ses_id));
		sgs[num_out++] = &ses_id_sg;
		sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
		sgs[num_out + num_in++] = &host_ret_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		crypt_operations = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);
		if(!crypt_operations){
			debug("Can't allocate memory for crypt_op");
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(crypt_operations, (struct  crypt_op *) arg, sizeof(struct crypt_op))){
			debug("copy from user");
			ret = -EFAULT;
			kfree(crypt_operations);
			goto fail;
		}
		sg_init_one(&crypt_op_sg, crypt_operations, sizeof(*crypt_operations));
		sgs[num_out++] = &crypt_op_sg;
		src = kzalloc(sizeof(unsigned char) * crypt_operations->len, GFP_KERNEL);
		if(!src){
			debug("Can't allocate memory for src");
			kfree(crypt_operations);
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(src, crypt_operations->src, sizeof(unsigned char) * crypt_operations->len)){
			debug("copy from user src");
			ret = -EFAULT;
			kfree(src);
			kfree(crypt_operations);
			goto fail;
		}
		sg_init_one(&src_sg, src, sizeof(*src));
		sgs[num_out++] = &src_sg;
		iv = kzalloc(sizeof(unsigned char) * 16, GFP_KERNEL);
		if(!iv){
			debug("Can't allocate memory for iv");
			kfree(crypt_operations);
			kfree(src);
			ret = -ENOMEM;
			goto fail;
		}
		if(copy_from_user(iv, crypt_operations->iv, sizeof(unsigned char) * 16)){
			debug("copy from user iv");
			ret = -EFAULT;
			kfree(iv);
			kfree(src);
			kfree(crypt_operations);
			goto fail;
		}
		sg_init_one(&iv_sg, iv, sizeof(*iv));
		sgs[num_out++] = &iv_sg;
		dst = kzalloc(sizeof(unsigned char) * crypt_operations->len, GFP_KERNEL);
		if(!dst){
			debug("Can't allocate memory for dst");
			kfree(iv);
			kfree(src);
			kfree(crypt_operations);
			ret = -ENOMEM;
			goto fail;
		}
		sg_init_one(&dst_sg, dst, sizeof(*dst));
		sgs[num_out + num_in++] = &dst_sg;
		sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
		sgs[num_out + num_in++] = &host_ret_sg;

		break;

	default:
		debug("Unsupported ioctl command");
		ret = -EINVAL;
		goto fail;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* Lock */
	spin_lock_irqsave(&crdev->lock, flags);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	if(err < 0){
		spin_unlock_irqrestore(&crdev->lock, flags);
		debug("Could not add buffers to vq");
		ret = -EINVAL;
		goto fail;
	}
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irqrestore(&crdev->lock, flags);

	switch(cmd){
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		if(*host_ret < 0){
			debug("Invalid ret value from host.");
			ret = -1;
			kfree(sess);
			kfree(key);
			goto fail;
		}
		if(copy_to_user((struct session_op *) arg, sess, sizeof(struct session_op))){
			debug("Can't copy sess to user.");
			ret = -1;
			kfree(sess);
			kfree(key);
			goto fail;
		}	
		kfree(sess);
		kfree(key);		
		break;
	case CIOCFSESSION:
		debug("CIOCFSESSION");
		if(*host_ret < 0){
			debug("Failed to close the session.");
			ret = -1;
			kfree(ses_id);
			goto fail;
		}
		kfree(ses_id);
		break;
	case CIOCCRYPT:
		debug("CIOCCRYPT");
		if(*host_ret < 0){
			debug("Invalid ret value from host.");
			ret = -1;
			kfree(dst);
			kfree(iv);
			kfree(src);
			kfree(crypt_operations);
			goto fail;
		}
		if(copy_to_user(((struct crypt_op *) arg)->dst, dst, crypt_operations->len * sizeof(unsigned char))){
			debug("Can't copy dst to user.");
			ret = -1;
			kfree(dst);
			kfree(iv);
			kfree(src);
			kfree(crypt_operations);
			goto fail;
		}
	}			

fail:
	if(ret >= 0)
		ret = *host_ret;
	kfree(cmd_ptr);
	kfree(host_ret);
	kfree(syscall_type);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
