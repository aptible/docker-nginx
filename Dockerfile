FROM quay.io/aptible/alpine

# ruby necessary for ERB
# curl necessary for integration tests
RUN apk-install ruby curl

ADD install-nginx /tmp/
RUN /tmp/install-nginx

# Generate a 2048-bit Diffie-Hellman group in line with recommendations
# at https://weakdh.org/sysadmin.html.
RUN openssl dhparam -out /etc/nginx/dhparams.pem 2048

ADD templates/etc /etc
ADD templates/bin /usr/local/bin

ADD test /tmp/test
# haproxy necessary for Proxy Protocol integration tests
# haproxy 1.5 is not in the mainline alpine repository as of this writing (Feb 15, 2015).
# cf. http://wiki.alpinelinux.org/wiki/Alpine_Linux_package_management#Add_a_Package
RUN apk-install haproxy openssl-dev --repository http://dl-4.alpinelinux.org/alpine/edge/main \
    && bats /tmp/test \
    && rm -rf /tmp/nginx/* \
    && apk del haproxy openssl-dev

VOLUME /etc/nginx/ssl

EXPOSE 80 443 9000

CMD ["/usr/local/bin/nginx-wrapper"]
