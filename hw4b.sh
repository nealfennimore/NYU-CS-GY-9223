#! /usr/bin/env bash

# set -o noglob noclobber pipefail

doit() {
    OUTPUT=$(printf "111\n0\n$1" | ./hand_rolled_cryptex)
}

export -f doit

for j in $(seq 0 1024); do
    echo $j | xxd -p -r
done

# parallel -j2048 doit ::: $(seq 255 1024)

# ./hand_rolled_cryptex
