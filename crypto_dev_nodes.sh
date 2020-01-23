#!/bin/bash

# Create the character device nodes for use with virtio-crypto
nr_devices=32

for i in $(seq 0 1 ${nr_devices}); do
	mknod /dev/cryptodev$i c 60 $i
done
