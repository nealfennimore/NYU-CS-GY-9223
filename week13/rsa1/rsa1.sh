#! /usr/bin/env bash
FILE="${1:-rsa1.txt}"
ATTACK="${2:-all}"

CONTENTS=$(cat "$FILE")

get_value() {
    echo "$CONTENTS" | grep "$1" | awk '{print $3}'
}

python3 RsaCtfTool/RsaCtfTool.py \
    --verbosity DEBUG \
    -n "$(get_value "n")" \
    -e "$(get_value "e")" \
    --uncipher "$(get_value "c")" \
    --timeout 600 \
    --attack "$ATTACK"
