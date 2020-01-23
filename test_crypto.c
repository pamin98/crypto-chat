/*                                                                       
 * test_crypto.c
 * 
 * Performs a simple encryption-decryption of urandom data from /dev/urandom 
 * with the use of cryptodev device.
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *                                                                               
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "cryptodev.h"
 
#include <sys/types.h>
#include <sys/stat.h>

#define DATA_SIZE       16384
#define BLOCK_SIZE      16
#define KEY_SIZE        24

int fill_urandom_buff(char in[DATA_SIZE]);

static int test_crypto(int cfd)
{
	struct session_op sess;
	struct crypt_op cryp;
	struct {
		char in[DATA_SIZE],
		     encrypted[DATA_SIZE],
		     decrypted[DATA_SIZE],
		     iv[BLOCK_SIZE],
		     key[KEY_SIZE];
	} data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	if (fill_urandom_buff(data.in) < 0) {		
		printf("error @filling urandom data\n");
		return 1;
	}

	//printf("Sleeping for 30 seconds. Its time to remove the host device.\n");
	//sleep(30);
	//printf("Woke up after 30 seconds.\n");

	/**
	 *  Get crypto session for AES128
	 **/
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = (__u8  __user *)data.key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	/**
	 *  Encrypt data.in to data.encrypted
	 **/
	printf("Doing encryption of %d bytes of data...", DATA_SIZE);
	fflush(stdout);
	cryp.ses = sess.ses;
	cryp.len = sizeof(data.in);
	cryp.src = (__u8 __user *)data.in;
	cryp.dst = (__u8 __user *)data.encrypted;
	cryp.iv = (__u8 __user *)data.iv;
	cryp.op = COP_ENCRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}
	printf("[OK]\n");

	/**
	 *  Decrypt data.encrypted to data.decrypted
	 **/
	printf("Doing decryption of %d bytes of data...", DATA_SIZE);
	fflush(stdout);
	cryp.src = (__u8 __user *)data.encrypted;
	cryp.dst = (__u8 __user *)data.decrypted;
	cryp.op = COP_DECRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}
	printf("[OK]\n");

	/**
	 *  Verify the result
	 **/
	printf("Doing Verification of data...");
	fflush(stdout);
	if (memcmp(data.in, data.decrypted, sizeof(data.in)) != 0) {
		printf(" Error\n");
		return 1;
	} else {
		printf(" Success\n");
	}

	/**
	 *  Finish crypto session 
	 **/
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}

	return 0;
}

int fill_urandom_buff(char in[DATA_SIZE]){
	int crypto_fd = open("/dev/urandom", O_RDONLY);
	int ret = -1;
	
	if (crypto_fd < 0)
		return crypto_fd;

	ret = read(crypto_fd, (void *)in, DATA_SIZE);

	close(crypto_fd);

	return ret;
}

int main(int argc, char **argv)
{
	int fd = -1;
	char *filename;
	char error_str[100];
	
	filename = (argv[1] == NULL) ? "/dev/crypto" : argv[1];
	fd = open(filename, O_RDWR, 0);
	printf("DONE\n");
	if (fd < 0) {
		sprintf(error_str, "open %s", filename);
		perror(error_str);
		return 1;
	}

	if (test_crypto(fd))
		return 1;

	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
