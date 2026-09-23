#!/bin/sh
# Configures Postfix from MAIL_HOSTNAME and optional TLS_CERT/TLS_KEY, then
# runs it in the foreground.
set -e
postconf -e \
  "myhostname=${MAIL_HOSTNAME}" \
  "inet_interfaces=all" \
  "inet_protocols=ipv4" \
  "maillog_file=/dev/stdout" \
  "compatibility_level=3.9"
if [ -n "$TLS_CERT" ]; then
  postconf -e "smtpd_tls_security_level=may" "smtpd_tls_chain_files=${TLS_KEY},${TLS_CERT}"
else
  postconf -e "smtpd_tls_security_level=none"
fi
exec postfix start-fg
