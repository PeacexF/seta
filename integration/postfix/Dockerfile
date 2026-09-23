FROM alpine:3.22
RUN apk add --no-cache postfix
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
