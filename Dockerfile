FROM quay.io/aptible/alpine:3.3

# ruby necessary for ERB
# curl necessary for integration tests
RUN apk-install ruby curl

# Install Nginx itself
ADD install-nginx /tmp/
RUN /tmp/install-nginx

# Generate a 2048-bit Diffie-Hellman group in line with recommendations
# at https://weakdh.org/sysadmin.html.
RUN openssl dhparam -out /etc/nginx/dhparams.pem 2048

ADD templates/html /usr/html/
ADD templates/etc /etc
ADD templates/bin /usr/local/bin

# Generate default error pages
RUN cd /usr/html \
 && ERROR_EMBED_PATH="50x.html.embed" erb error.html.erb > 50x.html \
 && ERROR_EMBED_PATH="hostname-filtering.html.embed" erb error.html.erb > hostname-filtering.html

RUN mkdir /html
ADD templates/html/acme-pending.html.erb /html/

ADD test /tmp/test
RUN apk-install haproxy openssl-dev \
 && bats /tmp/test \
 && rm -rf /tmp/nginx/* \
 && apk del haproxy openssl-dev

VOLUME /etc/nginx/ssl

EXPOSE 80 443 9000

CMD ["/usr/local/bin/nginx-wrapper"]
