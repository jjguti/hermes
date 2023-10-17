FROM alpine:3.18
ADD . /hermes
WORKDIR /hermes
RUN apk add --no-cache perl graphviz doxygen gcc make openssl-dev libspf2-dev cmake g++ sqlite-dev gettext-dev
RUN cmake -B build
RUN cmake --build build
RUN mkdir /hermes-installation
RUN cmake --install build --prefix /hermes-installation

FROM alpine:3.18
EXPOSE 25
COPY --from=0 /hermes-installation /hermes
RUN apk add --no-cache openssl libspf2 sqlite-libs libstdc++ libgcc
CMD ["/hermes/bin/hermes", "/config/hermesrc"]
