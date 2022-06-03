FROM alpine:3.13 AS build

RUN apk update && \
    apk add openssh tcpdump python3 py3-pip python3-dev && \
    apk add py3-matplotlib py3-wheel py3-numpy py3-scipy py3-pandas && \
    pip3 install seaborn
    
COPY stats.png /stats.png
COPY captureTraffic_createVisuals.py /captureTraffic_createVisuals.py
COPY causeTraffic.py /causeTraffic.py
COPY start.sh /start.sh
COPY index.html /index.html

RUN chmod 755 /start.sh

EXPOSE 8080

CMD ["/bin/sh","/start.sh"]
