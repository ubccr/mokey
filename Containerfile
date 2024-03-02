FROM docker.io/alpine:3.13

RUN touch /etc/krb5.conf
COPY mokey /usr/local/bin
COPY server/templates /usr/share/mokey/templates

ENTRYPOINT ["/usr/local/bin/mokey", "--conf", "/etc/mokey/mokey.yaml", "server"]
