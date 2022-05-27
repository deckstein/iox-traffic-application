#!/bin/sh

interface_ip=`ip addr show ${interface} | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"`

#cd /iox_data/appdata
/usr/bin/python3 -m http.server 8080 &

cd /webpages/cisco.com
/usr/bin/python3 -m http.server 8081 &

cd /webpages/devnet.com
/usr/bin/python3 -m http.server 8082 &

cd /webpages/ei-cisco.com
/usr/bin/python3 -m http.server 8083 &

/usr/bin/python3 /causeTraffic.py &

/usr/bin/python3 /captureTraffic_createVisuals.py ${interface} ${interface_ip} &

wait -n

exit $?
