# ![](https://gravatar.com/avatar/11d3bc4c3163e3d238d558d5c9d98efe?s=64) aptible/nginx

[![Docker Repository on Quay.io](https://quay.io/repository/aptible/nginx/status)](https://quay.io/repository/aptible/nginx)

NGiNX HTTP reverse proxy server.

## Installation and Usage

    docker pull quay.io/aptible/nginx
    docker run -P quay.io/aptible/nginx

To proxy to an upstream host(s) and port(s), set the `UPSTREAM_SERVERS` environment variable:

    docker run -P -e UPSTREAM_SERVERS=host1:3000,host2:4000 quay.io/aptible/nginx

The server starts with a default self-signed certificate. To load in your own certificate and private key, pass them in as mounted Docker "volumes." For example:

    docker run -v /path/to/server.key:/etc/nginx/ssl/server.key -v /path/to/server.crt:/etc/nginx/ssl/server.crt quay.io/aptible/nginx

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

### TCP proxies

To use NGiNX as a proxy to TCP upstreams, just set the `PROTOCOL` environment variable to `tcp`, and specify the following additional environment variables:

* `UPSTREAM_SERVER_PORTS`: A comma-separated array of ports on which NGiNX should listen.
* `UPSTREAM_SERVERS_#{port}`: A comma-separated array of upstreams that the listener on port `port` should proxy to. There should be one such value configured for each entry in `UPSTREAM_SERVER_PORTS`.

For example, the following invocation will run an NGiNX server listening on port 9000 and proxying requests to host1:3000:

    docker run -P -e PROTOCOL=tcp UPSTREAM_SERVER_PORTS=9000 UPSTREAM_SERVERS_9000=host1:3000 quay.io/aptible/nginx

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

* `latest`: Currently NGiNX 1.6.2

## Deployment

To push the Docker image to Quay, run the following command:

    make release

## Copyright and License

MIT License, see [LICENSE](LICENSE.md) for details.

Copyright (c) 2014 [Aptible](https://www.aptible.com) and contributors.

[<img src="https://s.gravatar.com/avatar/f7790b867ae619ae0496460aa28c5861?s=60" style="border-radius: 50%;" alt="@fancyremarker" />](https://github.com/fancyremarker)
