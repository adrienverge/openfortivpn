FROM alpine

WORKDIR /opt

RUN apk update

RUN apk add --update-cache \
    git autoconf automake pkgconfig gcc g++ libressl-dev make ppp-pppoe

COPY . ./

RUN ./autogen.sh && \
    ./configure --prefix=/usr/local --sysconfdir=/etc --disable-dependency-tracking && \
    make && \
    make install

ENTRYPOINT ["/usr/local/bin/openfortivpn"]

CMD ["-c", "/etc/openfortivpn/config"]
