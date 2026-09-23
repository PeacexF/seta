# Used by goreleaser, which places each platform's binary under $TARGETPLATFORM.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/seta /usr/bin/seta
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/seta"]
