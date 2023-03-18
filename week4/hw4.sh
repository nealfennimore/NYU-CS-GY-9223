#! /usr/bin/env bash

# set -o noglob noclobber pipefail

# exec 3<>/dev/tcp/offsec-chalbroker.osiris.cyber.nyu.edu/8005

# show_output() {
#     read -u 3 line
#     echo $line
# }

# # sleep 1
# # echo "nf2137" >&3;
# # show_output

# sleep 2
# show_output
# echo "My name is Sir Lancelot of Camelot." >&3

# sleep 1
# echo "0" >&3
# echo "15" >&3
# show_output

# exec 3>&-
# 18446744073709551615

# rm output

echo -n "0
0
15
195
237
85
100
84
85
252
35
195
49
98
36
107
65
255
67
202
191
" | ./bridge_of_death
