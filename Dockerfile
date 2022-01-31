FROM alpine
WORKDIR /
ADD . /hermes
WORKDIR /hermes
RUN apk add -t hermes-build-deps --no-cache perl graphviz doxygen gcc make openssl-dev libspf2-dev cmake g++ sqlite-dev gettext-dev
RUN cmake -B build
RUN cmake --build build
RUN mkdir /hermes-installation
RUN cmake --install build --prefix /hermes-installation

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
