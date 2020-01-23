/*
 * server-cryptodev.c
 * Encrypted TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "../cryptodev.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

struct session_op sess;

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = write(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

int encrypt(int cfd, unsigned char *buf){
    int i;
    struct crypt_op cryp;

    struct {
        unsigned char   encrypted[DATA_SIZE],
        iv[BLOCK_SIZE];
    } data;

    memset(&cryp, 0, sizeof(cryp));

    /*
     * Encrypt data.in to data.encrypted
     */
    cryp.ses = sess.ses;
    cryp.len = DATA_SIZE;
    cryp.src = buf;
    cryp.dst = data.encrypted;
    cryp.iv = iv;
    cryp.op = COP_ENCRYPT;

    if (ioctl(cfd, CIOCCRYPT, &cryp)) {
        perror("ioctl(CIOCCRYPT)");
        return 1;
    }

    i = 0;
    while(i < DATA_SIZE){//data.encrypted[i] != '\0'){
        buf[i] = data.encrypted[i];
        // printf("%x", data.encrypted[i]);
        i++;
    }

    return 0;
}

int decrypt(int cfd, unsigned char *buf){
    int i;
    struct crypt_op cryp;
    struct {
        unsigned char   decrypted[DATA_SIZE],
                        iv[BLOCK_SIZE];
    } data;

    memset(&cryp, 0, sizeof(cryp));

    /*
     * Decrypt data.encrypted to data.decrypted
     */
    cryp.ses = sess.ses;
    cryp.len = DATA_SIZE;
    cryp.src = buf;
    cryp.dst = data.decrypted;
    cryp.iv = iv;
    cryp.op = COP_DECRYPT;
    if (ioctl(cfd, CIOCCRYPT, &cryp)) {
        perror("ioctl(CIOCCRYPT)");
        return 1;
    }

    memset(buf, '\0', DATA_SIZE);
    fprintf(stdout, ">Peer says: ");
    fflush(stdout);
    i = 0;
    while(data.decrypted[i] != '\0'){
        buf[i] = data.decrypted[i];
        i++;
    }

    return 0;
}

int main(void){
    char addrstr[INET_ADDRSTRLEN];
    int sd, newsd;
    ssize_t n;
    unsigned char buf[DATA_SIZE];
    socklen_t len;
    struct sockaddr_in sa;
    int cfd;
        
    /* Make sure a broken connection doesn't kill us */
    signal(SIGPIPE, SIG_IGN);
    /* Create TCP/IP socket, used as main chat channel */
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    /* Bind to a well-known port */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(TCP_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);         //we don't need to bind a socket to a specific IP
    if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        exit(1);
    }
    fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

    /* Listen for incoming connections */
    if (listen(sd, TCP_BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }
    fd_set rdset;
    /* Loop forever, accept()ing connections */
    for (;;) {
        fprintf(stderr, "Waiting for an incoming connection...\n");

        /* Accept an incoming connection */
        len = sizeof(struct sockaddr_in);
        if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
            perror("accept");
            exit(1);
        }
        if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
            perror("could not format IP address");
            exit(1);
        }
        fprintf(stderr, "Incoming connection from %s:%d\n", addrstr, ntohs(sa.sin_port));

        cfd = open("/dev/cryptodev0", O_RDWR);
        if (cfd < 0) {
            perror("open(/dev/crypto)");
            return 1;
        }

		memset(&sess, 0, sizeof(sess));
        /*
         * Get crypto session for AES128
         */
        sess.cipher = CRYPTO_AES_CBC;
       	sess.keylen = KEY_SIZE;
        sess.key = key;
       	if (ioctl(cfd, CIOCGSESSION, &sess)) {
           	perror("ioctl(CIOCGSESSION)");
           	return 1;
       	}

		FD_ZERO(&rdset);

        /* We break out of the loop when the remote peer goes away */
        for (;;) {
            FD_SET(newsd, &rdset);
            FD_SET(0, &rdset);
            if (select(newsd+1, &rdset , NULL , NULL , NULL) < 0){
                perror("select");
                exit(1);
            }

            if(FD_ISSET(newsd, &rdset)) {
                n = read(newsd, buf, sizeof(buf));
                if (n <= 0) {
                    if(n < 0)
                        perror("read from peer failed");
                    else{
                        fprintf(stdout, "Peer left the session.\n");
                        fflush(stdout);
                    }
                    break;
                }
                                
                if(decrypt(cfd, buf)){
                    perror("decrypt");
                    exit(1);
                }

                if (insist_write(1, buf, DATA_SIZE) != DATA_SIZE) {
                    perror("write");
                    exit(1);
                }
            }

            if(FD_ISSET(0, &rdset)) {
                memset(buf, '\0', sizeof(buf));
			    n = read(0, buf, sizeof(buf));
                if (n < 0) {
                    perror("read");
                    exit(1);
                }

                if(encrypt(cfd, buf)){
                    perror("encrypt");
                    exit(1);
                }

                if (insist_write(newsd, buf, DATA_SIZE) != DATA_SIZE) {
                    perror("write");
                    exit(1);
                }
            }
        }

		/* Finish crypto session */
  		if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
           	perror("ioctl(CIOCFSESSION)");
       		return 1;
       	}

        if (close(cfd) < 0) {
            perror("close(cfd)");
            return 1;
        }

        /* Make sure we don't leak open files */
        if (close(newsd) < 0)
            perror("close");
    }

    /* This will never happen */
    return 1;
}

