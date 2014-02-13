#!/bin/bash
#Joseph Bonneau
#December 2005
#Generate a random 16-byte AES Key

dd if=/dev/random of=$1 bs=16 count=1 > /dev/null 2>/dev/null

echo "Key stored in file: " $1

