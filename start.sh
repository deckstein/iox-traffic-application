#!/bin/sh

interface_ip=`ip addr show ${interface} | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"`

cd /data/appdata
/usr/bin/python3 -m http.server 8080 &

/usr/bin/python3 /data/appdata/causeTraffic.py &

/usr/bin/python3 /data/appdata/captureTraffic_createVisuals.py ${interface} ${interface_ip} &

wait -n

exit $?
