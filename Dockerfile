FROM alpine:latest AS build

RUN apk update && \
    apk add make g++ jpeg-dev blas-dev blas openblas openblas-dev python3 py3-pip libxml2-dev libxslt-dev gcc libxml2 python3-dev linux-headers musl-dev  && \
    apk add py3-matplotlib py3-wheel py3-numpy py3-scipy py3-pandas && \
    pip3 install pyshark seaborn plotly && \
    mkdir -p /data/appdata



FROM alpine:latest

RUN apk update && \
    apk add python3 wireshark-common tshark
    
COPY --from=build /usr/lib/python3.8/site-packages/ /usr/lib/python3.8/site-packages/
COPY --from=build /usr/lib/libxml2.so.2 /usr/lib/
COPY --from=build /usr/lib/libxslt.so.1 /usr/lib/
COPY --from=build /usr/lib/libexslt.so.0 /usr/lib/
COPY --from=build /usr/lib/libgcrypt.so.20 /usr/lib/
COPY --from=build /usr/lib/libgpg-error.so.0 /usr/lib/
COPY --from=build /usr/lib/libopenblas.so.3 /usr/lib/
COPY --from=build /usr/lib/libgfortran.so.5 /usr/lib/
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=build /usr/lib/libfreetype.so.6 /usr/lib/
COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib/
COPY --from=build /usr/lib/libpng16.so.16 /usr/lib/
COPY --from=build /usr/lib/libbrotlidec.so.1 /usr/lib/
COPY --from=build /usr/lib/libbrotlicommon.so.1 /usr/lib/
COPY --from=build /usr/lib/libjpeg.so.8 /usr/lib/
COPY --from=build /usr/lib/libopenjp2.so.7 /usr/lib/
COPY --from=build /usr/lib/libimagequant.so.0 /usr/lib/
COPY --from=build /usr/lib/libtiff.so.5 /usr/lib/
COPY --from=build /usr/lib/libxcb.so.1 /usr/lib/
COPY --from=build /usr/lib/libXau.so.6 /usr/lib/
COPY --from=build /usr/lib/libXdmcp.so.6 /usr/lib/
COPY --from=build /usr/lib/libbsd.so.0 /usr/lib/
COPY *.py *.sh /data/appdata/

EXPOSE 8080

CMD ['/bin/sh','/data/appdata/start.sh']
