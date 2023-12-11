#!/bin/sh

while [ true ]; do
    su -l ctf -c "socat -dd TCP4-LISTEN:9000,fork,reuseaddr EXEC:'./chal.bin',pty,echo=0,raw,iexten=0 2> /dev/null"
done;
