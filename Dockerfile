FROM debian:bullseye-20230208-slim

WORKDIR /opt

RUN apt update

RUN apt install -y \
    git autoconf automake pkg-config gcc g++ libssl-dev make ppp-dev

COPY . ./


RUN ./autogen.sh && \
        ./configure --prefix=/usr/local --sysconfdir=/etc --disable-dependency-tracking && \
    make && make install

ENTRYPOINT ["/usr/local/bin/openfortivpn"]

CMD ["-c", "/etc/openfortivpn/config"]
