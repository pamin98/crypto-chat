/*
 * crypto-chrdev.h
 *
 * Definition file for the virtio-crypto character device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 *
 */

#ifndef _CRYPTO_CHRDEV_H
#define _CRYPTO_CHRDEV_H

/*
 * Crypto character device
 */
#define CRYPTO_CHRDEV_MAJOR 60  /* Reserved for local / experimental use */
#define CRYPTO_NR_DEVICES   32  /* Number of devices we support */

/*
 * Init and destroy functions.
 */
int crypto_chrdev_init(void);
void crypto_chrdev_destroy(void);

#endif	/* _CRYPTO_CHRDEV_H */ 
