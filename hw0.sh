#! /usr/bin/env bash

set -o noglob

exec 3<> /dev/tcp/offsec-chalbroker.osiris.cyber.nyu.edu/1236;

sleep 1
echo "nf2137" >&3;

DIGITS_EQUATION_REGEX="^[0-9]+[[:space:]].[[:space:]][0-9]+$"
DIGITS_REGEX="^[0-9]+$"
WORDS_REGEX="^[A-Z]+.+[A-Z]+$"
HEX_REGEX="^0x[a-f0-9]+$"
BINARY_REGEX="^0b[0-1]+$"

declare -A DIGITS=(
    ["ZERO"]="0"
    ["ONE"]="1"
    ["TWO"]="2"
    ["THREE"]="3"
    ["FOUR"]="4"
    ["FIVE"]="5"
    ["SIX"]="6"
    ["SEVEN"]="7"
    ["EIGHT"]="8"
    ["NINE"]="9"
)


while IFS= read -r line <&3; do
    echo "$line"
    if [[ $line =~ "= ?" ]]; then

        INITIAL_EQUATION="${line::-4}"
        if [[ $INITIAL_EQUATION =~ $DIGITS_EQUATION_REGEX ]]; then
            echo "$INITIAL_EQUATION" | bc >&3
        else

            EQUATION=""
            for PART in $(echo "$INITIAL_EQUATION" | tr " " "\n"); do
                if [[ $PART =~ $DIGITS_REGEX ]]; then
                    EQUATION+="$PART"
                elif [[ $PART =~ $HEX_REGEX ]]; then
                    HEX="${PART:2}"
                    EQUATION+="$((16#${HEX^^}))"
                elif [[ $PART =~ $BINARY_REGEX ]]; then
                    BINARY="${PART:2}"
                    EQUATION+="$((2#$BINARY))"
                elif [[ $PART =~ $WORDS_REGEX ]]; then
                    for WORD in $(echo "$PART" | tr "-" "\n"); do
                        EQUATION+="${DIGITS[$WORD]}"
                    done
                else 
                    EQUATION+="$PART"
                fi

                EQUATION+=" "
            done

            echo "$EQUATION" | bc >&3
        fi
    fi
done


exec 3>&-

