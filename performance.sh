#!/bin/bash

PROG="fim_db"

dt=$(date '+%d/%m/%Y %H:%M:%S')
echo -ne "\e[31m$dt - INFO: "$PROG" started.\e[39m\n"
START_TIME=$(date +%s)
./$PROG mem /root/test 1 /root/test/file_01000.txt > output.txt &

LAST_CPU=100
MAX_CPU=0
LAST_MEM=0
MAX_MEM=0

while true; do
    CHANGED=0
    PS=`ps -axo comm,%cpu,rss | grep "$PROG" | head -n1`
    CPU=`echo "$PS" | sed -En "s/^$PROG[[:blank:]]+([0-9.]+)[[:blank:]]+[0-9]+/\1/p"`
    MEM=`echo "$PS" | sed -En "s/^$PROG[[:blank:]]+[0-9.]+[[:blank:]]+([0-9]+)/\1/p"`

    if [ "$CPU" == "" ]; then
        END_TIME=$(date +%s)
        dt=$(date '+%d/%m/%Y %H:%M:%S')
        echo -ne "\n\e[31m$dt - INFO: "$PROG" finished. Time elapsed: $(($END_TIME - $START_TIME)) seconds.\e[39m\n"
        MAX=0
        break
    fi
    if (( $(echo "$LAST_CPU != $CPU" | bc -l) )); then
        LAST_CPU=$CPU
        if (( $(echo "$LAST_CPU > $MAX_CPU" | bc -l) )); then
            MAX_CPU=$LAST_CPU
        fi
        CHANGED=1
    fi
    if (( $(echo "$LAST_MEM != $MEM" | bc -l) )); then
        LAST_MEM=$MEM
        if (( $(echo "$LAST_MEM > $MAX_MEM" | bc -l) )); then
            MAX_MEM=$LAST_MEM
        fi
        CHANGED=1
    fi
    if [ $CHANGED == 1 ]; then
        dt=$(date '+%d/%m/%Y %H:%M:%S')
        echo -ne "$dt - Running "$PROG" -> Current CPU: $CPU %, Max: $MAX_CPU % | Current Memory: $MEM KB, Max: $MAX_MEM KB      \r"
    fi
done
