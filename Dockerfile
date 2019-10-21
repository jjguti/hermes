FROM alpine
WORKDIR /
ADD . /hermes
RUN cd /hermes && \
    apk add -t hermes-build-deps --no-cache gcc make openssl-dev libspf2-dev autoconf automake g++ sqlite-dev gettext-dev && \
    sh bootstrap && \
    ./configure && \
    make -j4 && \
    make install prefix=/hermes-installation

FROM alpine
EXPOSE 25
COPY --from=0 /hermes-installation /
WORKDIR /
RUN apk add --no-cache openssl libspf2 sqlite-libs libstdc++ libgcc && \
    mkdir /etc/hermes && \
    apk add --no-cache openssl libspf2 sqlite-libs libstdc++ libgcc && \
    openssl genrsa 1024 > /etc/hermes/hermes.key && \
    openssl req -new -x509 -nodes -sha1 -days 365 -subj /C=SE/ST=State/L=Location/O=Organization/OU=Unit/CN=commonname.com -key /etc/hermes/hermes.key > /etc/hermes/hermes.cert
COPY --from=0 /hermes/dists/hermesrc.example /etc/hermes/hermesrc
RUN sed -e "s#background = true#background = false#" -i /etc/hermes/hermesrc && \
    mkdir /var/hermes && \
    chown nobody:nobody -R /var/hermes
CMD ["hermes", "/etc/hermes/hermesrc"]
