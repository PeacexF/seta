# Used by goreleaser, which places each platform's binary under $TARGETPLATFORM.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/seta /usr/bin/seta
# The image has no shell to mkdir with; copying the (empty) home directory
# creates a state directory the nonroot user can write, which Docker copies
# into a new named volume mounted there.
COPY --from=gcr.io/distroless/static-debian12:nonroot --chown=nonroot:nonroot /home/nonroot /var/lib/seta
WORKDIR /var/lib/seta
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/seta"]
