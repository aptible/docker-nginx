# ![](https://gravatar.com/avatar/11d3bc4c3163e3d238d558d5c9d98efe?s=64) aptible/nginx

[![Docker Repository on Quay.io](https://quay.io/repository/aptible/nginx/status)](https://quay.io/repository/aptible/nginx)

NGiNX HTTP reverse proxy server.

## Intended Use

The `aptible/nginx` image is used for proxy containers that handle SSL/TLS
termination and same-instance load balancing for Aptible Deploy
[Endpoints](https://www.aptible.com/documentation/deploy/reference/apps/endpoints.html#endpoints).
For customers, we recommend using the [official `nginx` image](https://hub.docker.com/_/nginx)
instead or forking this project if you would like to modify it for your own use.

## Installation and Usage

    docker pull quay.io/aptible/nginx
    docker run -P quay.io/aptible/nginx

To proxy to an upstream host(s) and port(s), set the `UPSTREAM_SERVERS` environment variable:

    docker run -P -e UPSTREAM_SERVERS=host1:3000,host2:4000 quay.io/aptible/nginx

The server starts with a default self-signed certificate. To load in your own certificate and private key, pass them in as mounted Docker "volumes." For example:

    docker run -v /path/to/server.key:/etc/nginx/ssl/server.key -v /path/to/server.crt:/etc/nginx/ssl/server.crt quay.io/aptible/nginx

Alternatively, you can provide these via the `SSL_CERTIFICATE` and `SSL_KEY` environment variables.

To force SSL, set the `FORCE_SSL` environment variable to `true`:

    docker run -e FORCE_SSL=true quay.io/aptible/nginx

### Configuring supported protocols and cipher suites

The default set of protocols and cipher suites exposed in our NGiNX
configuration aims to balance security and compatibility with older clients.
This default configuration mitigates the POODLE vulnerabilities by only allowing
SSLv3 with the RC4 cipher. At the same time, it's accomodating enough to support
even a default installation of IE6 on Windows XP or use as a custom origin
behind AWS CloudFront over SSLv3/TLS1.

There is, however, mounting evidence that RC4 is broken, which would mean that
SSLv3 could not be used safely at all. To use a configuration that trades some
compatibility for security set the `DISABLE_WEAK_CIPHER_SUITES` environment
variable to `true`:

    docker run -e DISABLE_WEAK_CIPHER_SUITES=true quay.io/aptible/nginx

This flag turns off SSLv3 as well as the RC4 cipher. The configuration it
generates earns an A+ on the Qualys SSL Labs
[SSL Server Test](https://www.ssllabs.com/ssltest/) while providing
compatibility with almost all clients that Qualys tests. The lone exception is
IE 6 on Windows XP, which only fails because Qualys tests the default
installation: if TLS 1.0 is enabled in IE 6, our configuration can be used to
connect.

To allow more control over the ciphers and protocols used by NGiNX, we also
recognize the environment variables `SSL_CIPHERS_OVERRIDE` and
`SSL_PROTOCOLS_OVERRIDE` which can be used to completely override the NGiNX
`ssl_ciphers` and `ssl_protocols` settings. For example, to remove TLS 1.0 from
the available list of protocols but keep the rest of the
`DISABLE_WEAK_CIPHER_SUITES` settings, use `SSL_PROTOCOLS_OVERRIDE` to specify
support for only TLS 1.1 and 1.2:

    docker run -e DISABLE_WEAK_CIPHER_SUITES=true SSL_PROTOCOLS_OVERRIDE="TLSv1.1 TLSv1.2" quay.io/aptible/nginx

Since both `SSL_PROTOCOLS_OVERRIDE` and `SSL_CIPHERS_OVERRIDE` are injected
verbatim into the NGiNX configuration, a syntax error in either can keep NGiNX
from starting.

### Simulating trusted SSL connections

If you're on OS X running boot2docker, you can configure your system to trust NGiNX's self-signed certificate by taking the following steps:

1. Add an entry to your /etc/hosts file mapping "example.com" to your Docker IP address:

        sudo echo $(boot2docker ip 2>/dev/null) example.com >> /etc/hosts

1. Start your NGiNX container (daemonized), and copy the automatically-generated certificate to a temporarily file, then open it (in Keychain).

        ID=$(docker run -d -p 80:80 -p 443:443 quay.io/aptible/nginx)
        docker cp ${ID}:/etc/nginx/ssl/server.crt /tmp/
        open /tmp/server.crt

1. Choose to "always trust" it within Keychain.

1. Visit https://example.com and see the trusted certificate.


## Available Tags

* `latest`: Currently NGiNX 1.19.1

## Deployment

To push the Docker image to Quay, run the following command:

    make release

## Copyright and License

MIT License, see [LICENSE](LICENSE.md) for details.

Copyright (c) 2019 [Aptible](https://www.aptible.com) and contributors.
