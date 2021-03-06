#!/bin/sh

interface_ip=`ip addr show ${interface} | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"`

cd /
/usr/bin/python3 -m http.server 8080 &

/usr/bin/python3 /causeTraffic.py &

/usr/bin/python3 /captureTraffic_createVisuals.py ${interface} ${interface_ip} &

wait -n

exit $?
