#!/usr/bin/env bats

export UPSTREAM_OUT="/tmp/app.log"
export NGINX_OUT="/tmp/nginx.log"

HEALTH_PORT="9000"
HEALTH_ROUTE=.aptible/alb-healthcheck
BODY_DELAY=20 # Must be longer than the default client_body_timeout

install_heartbleed() {
  export GOPATH=/tmp/gocode
  export PATH=${PATH}:/usr/local/go/bin:${GOPATH}/bin
  go get github.com/FiloSottile/Heartbleed
  go install github.com/FiloSottile/Heartbleed
}

uninstall_heartbleed() {
  rm -rf ${GOPATH}
}

wait_for() {
  for i in $(seq 0 50); do
    if "$@" > /dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  return 1
}

wait_for_nginx() {
  /usr/local/bin/nginx-wrapper > "$NGINX_OUT" 2>&1 &
  wait_for pgrep -x "nginx: worker process"
  wait_for nc -z localhost 80
  wait_for nc -z localhost 443
}

wait_for_proxy_protocol() {
  # This is really weird, but it appears nginx takes several seconds to
  # correctly handle Proxy Protocol requests
  haproxy -f ${BATS_TEST_DIRNAME}/haproxy.cfg
  wait_for curl localhost:8080
}

local_s_client() {
  echo OK | openssl s_client -connect 127.0.0.1:443 $@
}

simulate_upstream() {
  BATS_TEST_DIRNAME="$BATS_TEST_DIRNAME" "$BATS_TEST_DIRNAME"/upstream-server &
}

setup() {
  TMPDIR=$(mktemp -d)
  cp /usr/html/* "$TMPDIR"
  ps auxwww
}

teardown() {
  echo "---- BEGIN NGINX LOGS ----"
  cat "$NGINX_OUT" || true
  rm -f "$NGINX_OUT"
  echo "---- END NGINX LOGS ----"

  echo "---- BEGIN APP LOGS ----"
  cat /tmp/app.log || true
  rm -f /tmp/app.log
  echo "---- END APP LOGS ----"

  pkill -KILL nginx-wrapper || true
  pkill -KILL nginx || true
  pkill -KILL -f upstream-server || true
  pkill -KILL nc || true
  pkill -KILL haproxy || true
  rm -rf /etc/nginx/ssl/*
  cp "$TMPDIR"/* /usr/html
}

simulate_slow_body() {
  # Simulates a slow body request by delaying sending the body for the provided
  # number of seconds. Upstream server must be running as nginx will return a
  # 405 method not allowed before sending the body.

  # File descriptor 3 is being used for something else so use 4
  # Connect to the server via TCP socket so we can control how the body is sent
  exec 4<>/dev/tcp/localhost/80

  # Send the request headers
  echo -ne "POST / HTTP/1.1\r
Host: localhost\r
Connection: close\r
Content-Length: 4\r\n\n" >&4

  # Send the "test" body text in 2 parts with the provided delay in between
  echo -ne "te" >&4
  sleep $1
  echo -ne "st" >&4

  # Attempt to read the response and timeout after 5 seconds
  # in case the connection remained open for some reason
  timeout -t 5 cat <&4

  # Close the file descriptor/connection
  exec 4<&-
  exec 4>&-
}

NGINX_VERSION=1.19.1

@test "It should install nginx $NGINX_VERSION" {
  run /usr/sbin/nginx -v
  [[ "$output" =~ "$NGINX_VERSION"  ]]
}

@test "It should install a 1.0.2 version of OpenSSL" {
  openssl version | grep "1.0.2"
}

@test "It unfortunately shows a LuaJIT warning." {
  wait_for_nginx

  # We can/should install resty-core if/when it is packaged for alpine.
  # https://gitlab.alpinelinux.org/alpine/aports/issues/10478
  grep "detected a LuaJIT version which is not" "$NGINX_OUT"
}

@test "It does not show a lua_load_resty_core error" {
  wait_for_nginx

  ! grep "lua_load_resty_core failed to load the resty.core module" "$NGINX_OUT"
}

@test "It does not emit any configuration deprecation warnings." {
  wait_for_nginx
  ! grep -i "deprecated" "$NGINX_OUT"
}

@test "It does not include the Nginx version" {
  wait_for_nginx
  run curl -v http://localhost
  echo "$output"
  [[ ! "$output" =~ "$NGINX_VERSION" ]]
}

@test "It allows configuring worker_connections" {
  WORKER_CONNECTIONS=123 wait_for_nginx
  grep "worker_connections 123" /etc/nginx/nginx.conf
}

@test "It allows passing a certificate via the environment" {
  openssl req -x509 -batch -nodes -newkey rsa:1024 \
    -keyout nginx.key -out nginx.crt \
    -subj /CN=hello-test-cert

  SSL_CERTIFICATE="$(cat nginx.crt)" SSL_KEY="$(cat nginx.key)" wait_for_nginx
  rm nginx.crt nginx.key

  run curl -kv https://localhost
  [[ "$output" =~ "hello-test-cert" ]]
}

@test "It allows passing a certificate via files" {
  openssl req -x509 -batch -nodes -newkey rsa:1024 \
    -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt \
    -subj /CN=hello-test-cert

  wait_for_nginx

  run curl -kv https://localhost
  [[ "$output" =~ "hello-test-cert" ]]
}

@test "It should pass an external Heartbleed test" {
  skip
  install_heartbleed
  wait_for_nginx
  Heartbleed 127.0.0.1:443
  uninstall_heartbleed
}

@test "It should accept large file uploads" {
  dd if=/dev/zero of=zeros.bin count=1024 bs=4096
  wait_for_nginx
  run curl -k --form upload=@zeros.bin --form press=OK https://127.0.0.1:443/
  [ "$status" -eq "0" ]
  [[ ! "$output" =~ "413"  ]]
}

@test "It should log to STDOUT" {
  wait_for_nginx
  curl -H 'Host: test.host' localhost > /dev/null 2>&1
  wait_for grep -i 'test.host' "$NGINX_OUT"
}

@test "It should log to STDOUT (HTTP + Proxy Protocol)" {
  PROXY_PROTOCOL=true wait_for_nginx
  wait_for_proxy_protocol
  curl -H 'Host: test.host' 127.0.0.1:8080 > /dev/null 2>&1
  wait_for grep -i 'test.host' "$NGINX_OUT"
}

@test "It should log to STDOUT (HTTPS)" {
  CIPHER="ECDHE-RSA-AES128-GCM-SHA256"
  wait_for_nginx
  curl -k --tlsv1.2 --ciphers "$CIPHER" -H 'Host: test.host' https://localhost \
    > /dev/null 2>&1
  wait_for grep -i 'test.host' "$NGINX_OUT"
  wait_for grep -i 'TLSv1.2' "$NGINX_OUT"
  wait_for grep -i "$CIPHER" "$NGINX_OUT"
}

@test "It should log to STDOUT (HTTPS + Proxy Protocol)" {
  CIPHER="ECDHE-RSA-AES128-GCM-SHA256"
  PROXY_PROTOCOL=true wait_for_nginx
  wait_for_proxy_protocol
  curl -k --tlsv1.2 --ciphers "$CIPHER" -H 'Host: test.host' https://127.0.0.1:8443 \
    > /dev/null 2>&1
  wait_for grep -i 'test.host' "$NGINX_OUT"
  wait_for grep -i 'TLSv1.2' "$NGINX_OUT"
  wait_for grep -i "$CIPHER" "$NGINX_OUT"
}

@test "It should accept and configure a MAINTENANCE_PAGE_URL" {
  UPSTREAM_SERVERS=127.0.0.1:4000 \
    MAINTENANCE_PAGE_URL=https://www.aptible.com/404.html wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "status.aptible.com" ]]
}

@test "It should accept a list of UPSTREAM_SERVERS" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should accept a list of UPSTREAM_SERVERS (Proxy Protocol)" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol
  run curl 127.0.0.1:8080 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should handle HTTPS over Proxy Protocol" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol
  run curl -k https://127.0.0.1:8443 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should honor FORCE_SSL" {
  FORCE_SSL=true wait_for_nginx
  run curl -I localhost 2>/dev/null
  [[ "$output" =~ "HTTP/1.1 301 Moved Permanently" ]]
  [[ "$output" =~ "Location: https://localhost" ]]
}

@test "It should send a Strict-Transport-Security header with FORCE_SSL" {
  FORCE_SSL=true wait_for_nginx
  run curl -Ik https://localhost 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security: max-age=31536000" ]]
}

@test "It should send a Strict-Transport-Security header with FORCE_SSL even on error responses" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 FORCE_SSL=true wait_for_nginx
  run curl -Ik https://localhost 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security: max-age=31536000" ]]
}

@test "The Strict-Transport-Security header's max-age should be configurable" {
  FORCE_SSL=true HSTS_MAX_AGE=1234 wait_for_nginx
  run curl -Ik https://localhost 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security: max-age=1234" ]]
}

@test "Its OpenSSL client should support TLS_FALLBACK_SCSV" {
  FORCE_SSL=true wait_for_nginx
  run local_s_client -fallback_scsv
  [ "$status" -eq "0" ]
}

@test "It should support TLS_FALLBACK_SCSV by default" {
  FORCE_SSL=true wait_for_nginx
  run local_s_client -fallback_scsv -no_tls1_2
  [ "$status" -ne "0" ]
  [[ "$output" =~ "inappropriate fallback" ]]
}

@test "It should use at least a 2048 EDH key" {
  # TODO: re-enable this test once we're using OpenSSL v.1.0.2 or greater.
  skip
  FORCE_SSL=true wait_for_nginx
  run local_s_client -cipher "EDH"
  [[ "$output" =~ "Server Temp Key: DH, 2048 bits" ]]
}

@test "It should have at least a 2048 EDH key available" {
   # TODO: remove this test in favor of the previous test once possible.
   run openssl dhparam -in /etc/nginx/dhparams.pem -check -text
   [[ "$output" =~ "DH Parameters: (2048 bit)" ]]
}

@test "It disables export ciphers" {
  FORCE_SSL=true wait_for_nginx
  run local_s_client -cipher "EXP"
  [ "$status" -eq 1 ]
}

@test "It allows RC4 for SSLv3" {
  wait_for_nginx
  run local_s_client -cipher "RC4" -ssl3
  [ "$status" -eq 0 ]
}

@test "It disables block ciphers for SSLv3" {
  wait_for_nginx
  run local_s_client -cipher "AES" -ssl3
  [ "$status" -ne 0 ]
}

@test "It support block ciphers for TLSv1.x" {
  wait_for_nginx
  run local_s_client -cipher "AES" -tls1_2
  [ "$status" -eq 0 ]
}

@test "It allows CloudFront-supported ciphers when using SSLv3" {
  # To mitigate POODLE attacks, we don't allow ciphers running in CBC mode under SSLv3.
  # This leaves only RC4-MD5 as an option for custom origins behind CloudFront. See
  # http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html
  # for more detail.
  wait_for_nginx
  run local_s_client -cipher "RC4-MD5" -ssl3
  [ "$status" -eq 0 ]
}

@test "It ignores invalid headers by default" {
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl --header "Periods.Are.Invalid: true" --max-time 1 http://localhost
  run cat /tmp/nc.log
  [[ ! "$output" =~ "Periods.Are.Invalid: true" ]]
}

@test "It can allow invalid headers" {
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  IGNORE_INVALID_HEADERS=off UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl --header "Periods.Are.Invalid: false" --max-time 1 http://localhost
  run cat /tmp/nc.log
  [[ "$output" =~ "Periods.Are.Invalid: false" ]]
}

@test "It allows underscores in headers" {
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl --header "NoUnderscores: true" --header "SOME_UNDERSCORES: true" --max-time 1 http://localhost
  run cat /tmp/nc.log
  [[ "$output" =~ "NoUnderscores: true" ]]
  [[ "$output" =~ "SOME_UNDERSCORES: true" ]]
}

@test "It does not allow SSLv3 if DISABLE_WEAK_CIPHER_SUITES is set" {
  DISABLE_WEAK_CIPHER_SUITES=true wait_for_nginx
  run local_s_client -ssl3
  [ "$status" -eq 1 ]
}

@test "It does not allow RC4 if DISABLE_WEAK_CIPHER_SUITES is set" {
  DISABLE_WEAK_CIPHER_SUITES=true wait_for_nginx
  run local_s_client -cipher "RC4"
  [ "$status" -eq 1 ]
}

@test "It allows ssl_ciphers to be overridden with SSL_CIPHERS_OVERRIDE" {
  SSL_CIPHERS_OVERRIDE="ECDHE-RSA-AES256-GCM-SHA384" wait_for_nginx
  run local_s_client -cipher ECDHE-RSA-AES256-GCM-SHA384
  [ "$status" -eq 0 ]
  run local_s_client -cipher ECDHE-ECDSA-AES256-GCM-SHA384
  [ "$status" -eq 1 ]
  run local_s_client -cipher ECDHE-RSA-AES128-GCM-SHA256
  [ "$status" -eq 1 ]
  run local_s_client -cipher DES-CBC-SHA
  [ "$status" -eq 1 ]
}

@test "It allows ssl_protocols to be overridden with SSL_PROTOCOLS_OVERRIDE" {
  SSL_PROTOCOLS_OVERRIDE="TLSv1.1 TLSv1.2" wait_for_nginx
  run local_s_client -ssl3
  [ "$status" -eq 1 ]
  run local_s_client -tls1
  [ "$status" -eq 1 ]
  run local_s_client -tls1_1
  [ "$status" -eq 0 ]
  run local_s_client -tls1_2
  [ "$status" -eq 0 ]
}

@test "It removes any semicolons in SSL_CIPHERS_OVERRIDE" {
  SSL_CIPHERS_OVERRIDE="ECDHE;;-RSA-AES256-GCM-SHA384;" wait_for_nginx
  run local_s_client -cipher ECDHE-RSA-AES256-GCM-SHA384
  [ "$status" -eq 0 ]
}

@test "It removes any semicolons in SSL_PROTOCOLS_OVERRIDE" {
  SSL_PROTOCOLS_OVERRIDE=";;;TLSv1.1; TLSv1.2;" wait_for_nginx
  run local_s_client -tls1_1
  [ "$status" -eq 0 ]
}

@test "It sets an X-Request-Start header" {
  # https://docs.newrelic.com/docs/apm/applications-menu/features/request-queue-server-configuration-examples#nginx
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl --max-time 1 http://localhost
  run cat /tmp/nc.log
  [[ "$output" =~ "X-Request-Start: t=" ]]
}

@test "It forces X-Forwarded-Proto = http for HTTP requests" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -s -H 'X-Forwarded-Proto: https' http://localhost

  grep 'X-Forwarded-Proto: http' "$UPSTREAM_OUT"
  run grep 'X-Forwarded-Proto: https' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It forces X-Forwarded-Proto = https for HTTPS requests" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -sk -H 'X-Forwarded-Proto: http' https://localhost

  grep 'X-Forwarded-Proto: https' "$UPSTREAM_OUT"
}

@test "It drops the Proxy header (HTTP)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -s -H 'Proxy: some' http://localhost

  run grep -i 'Proxy:' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It drops the Proxy header (HTTP, lowercase)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -s -H 'proxy: some' http://localhost

  run grep -i 'Proxy:' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It drops the Proxy header (HTTPS)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -sk -H 'Proxy: some' https://localhost

  run grep -i 'Proxy:' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It drops the X-Aptible-Health-Check header (HTTP)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -s -H 'X-Aptible-Health-Check: some' http://localhost

  wait_for grep -i 'get' "$UPSTREAM_OUT"
  run grep -i 'X-Aptible-Health-Check:' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It drops the X-Aptible-Health-Check header (HTTPS)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -sk -H 'X-Aptible-Health-Check: some' https://localhost

  wait_for grep -i 'get' "$UPSTREAM_OUT"
  run grep -i 'X-Aptible-Health-Check:' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "It logs the X-Amzn-Trace-Id header for ALB Endpoints." {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -sk -H 'X-Amzn-Trace-Id: Root=1-67891233-abcdef012345678912345678' https://localhost

  wait_for grep -i 'get' "$NGINX_OUT"
  run grep -i 'Root=1-67891233-abcdef012345678912345678' "$NGINX_OUT"
  [[ "$status" -eq 0 ]]
}

@test "It logs the X-forwarded-for header." {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  curl -sk -H 'X-Forwarded-For: 8.2.4.6' https://localhost

  wait_for grep -i 'get' "$NGINX_OUT"
  run grep -i '8.2.4.6' "$NGINX_OUT"
  [[ "$status" -eq 0 ]]
}

@test "It supports GZIP compression of responses" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl -v --compressed localhost
  [[ "$status" -eq 0 ]]
  [[ "$output" =~ "Content-Encoding: gzip" ]]
  [[ "$output" =~ "Hello World" ]]
}

@test "It includes an informative default error page" {
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl http://localhost
  [[ "$output" =~ "application crashed" ]]
  [[ "$output" =~ "you are a visitor" ]]
  [[ "$output" =~ "you are the owner" ]]
}

@test "It redirects ACME requests if ACME_SERVER is set" {
  UPSTREAM_PORT=5000 UPSTREAM_RESPONSE="acme.txt" simulate_upstream
  simulate_upstream
  ACME_SERVER=127.0.0.1:5000 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl "http://localhost/.well-known/acme-challenge/123"
  [[ "$output" =~ 'ACME Response' ]]
  run curl "http://localhost/"
  [[ "$output" =~ 'Hello World!' ]]
}

@test "It redirects ACME requests if ACME_REDIRECT_HOST is set" {
  UPSTREAM_PORT=5000 UPSTREAM_RESPONSE="acme.txt" simulate_upstream
  simulate_upstream

  # NOTE: aptible.in won't actually resolve, but that's OK. What we need here is
  # a domain that will not rediredct any further. Not resolving achieves that.
  ACME_REDIRECT_HOST=aptible.in UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -Ls -o /dev/null -w '%{url_effective}' "http://localhost/.well-known/acme-challenge/123"
  [[ "$output" = 'http://aptible.in/.well-known/acme-challenge/123' ]]

  run curl -Lsk -o /dev/null -w '%{url_effective}' "https://localhost/.well-known/acme-challenge/123"
  [[ "$output" = 'https://aptible.in/.well-known/acme-challenge/123' ]]

  run curl "http://localhost/"
  echo "$output"
  [[ "$output" =~ 'Hello World!' ]]
}

@test "It does not redirect ACME requests if neither ACME_SERVER or ACME_REDIRECT_HOST is set" {
  UPSTREAM_PORT=5000 UPSTREAM_RESPONSE="acme.txt" simulate_upstream
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl "http://localhost/.well-known/acme-challenge/123"
  [[ "$output" =~ 'Hello World!' ]]
  run curl "http://localhost/"
  [[ "$output" =~ 'Hello World!' ]]
}

@test "It serves a static information page if ACME_PENDING is set" {
  ACME_PENDING="true" ACME_DOMAIN="some.domain.com" wait_for_nginx
  run curl "http://localhost/.well-known/acme-challenge/123"
  [[ "$output" =~ 'some.domain.com' ]]
  [[ "$output" =~ 'finish setting up' ]]
  run curl "http://localhost/"
  [[ "$output" =~ 'some.domain.com' ]]
  [[ "$output" =~ 'finish setting up' ]]
}

@test "When ACME is ready, it doesn't redirect to SSL without FORCE_SSL" {
  ACME_READY="true" wait_for_nginx

  run curl -sI localhost 2>/dev/null
  [[ "$output" =~ "HTTP/1.1 200 OK" ]]
  [[ ! "$output" =~ "HTTP/1.1 301 Moved Permanently" ]]

  run curl -Ik https://localhost 2>/dev/null
  [[ ! "$output" =~ "Strict-Transport-Security:" ]]
}

@test "When ACME is ready with FORCE_SSL, it redirects to SSL and sets HSTS headers" {
  ACME_READY="true" FORCE_SSL="true" wait_for_nginx

  run curl -I localhost 2>/dev/null
  [[ "$output" =~ "HTTP/1.1 301 Moved Permanently" ]]
  [[ "$output" =~ "Location: https://localhost" ]]

  run curl -Ik https://localhost 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security:" ]]
}

@test "Port ${HEALTH_PORT}: Nginx accepts plain HTTP requests" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"
}

@test "Port ${HEALTH_PORT}: Nginx rewrites the request path to /healthcheck" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://127.0.0.1:${HEALTH_PORT}/foo"
  wait_for grep 'GET /healthcheck' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "Port ${HEALTH_PORT}: Nginx discards headers" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs -H 'Authorization: foo' "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "Port ${HEALTH_PORT}: Nginx sets X-Aptible-Health-Check" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep -i 'X-Aptible-Health-Check' "$UPSTREAM_OUT"
}

@test "Port ${HEALTH_PORT}: Nginx rewrites the User-Agent header to Aptible Health Check" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep 'Aptible Health Check' "$UPSTREAM_OUT"
}

@test "Port ${HEALTH_PORT}: Nginx discards the request body" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs --data "foo=bar" "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "Port ${HEALTH_PORT}: Nginx discards the request method" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs -I "http://127.0.0.1:${HEALTH_PORT}/"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'head' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "Port ${HEALTH_PORT}: Nginx discards the response body" {
  simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol

  run curl http://127.0.0.1:8080/
  [[ "$output" =~ "Hello World!" ]]

  run curl "http://127.0.0.1:${HEALTH_PORT}/"
  [[ ! "$output" =~ "Hello World!" ]]
}

@test "Port ${HEALTH_PORT}: Nginx returns a 502 if the upstream is not responding" {
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -sw "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}/"
  [[ "$output" -eq 502 ]]
}

@test "Port ${HEALTH_PORT}: Nginx returns a 200 if the upstream is returning a 200" {
  UPSTREAM_RESPONSE="upstream-response.txt" simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -sw "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}/"
  [[ "$output" -eq 200 ]]
}

@test "Port ${HEALTH_PORT}: Nginx returns a 200 if the upstream is returning a 500" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -sw "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}/"
  [[ "$output" -eq 200 ]]
}

@test "Port ${HEALTH_PORT}: Nginx returns a 200 if FORCE_HEALTHCHECK_SUCCESS = true" {
  FORCE_HEALTHCHECK_SUCCESS=true PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -sw "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}/"
  [[ "$output" -eq 200 ]]
}

@test "Port ${HEALTH_PORT}: Nginx supports STRICT_HEALTH_CHECKS = true (200)" {
  simulate_upstream
  STRICT_HEALTH_CHECKS=true PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}")"
  [[ "$status" == "200" ]]
}

@test "Port ${HEALTH_PORT}: Nginx supports STRICT_HEALTH_CHECKS = true (302)" {
  UPSTREAM_RESPONSE="upstream-response-302.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}")"
  [[ "$status" == "302" ]]
}

@test "Port ${HEALTH_PORT}: Nginx supports STRICT_HEALTH_CHECKS = true (500)" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true PROXY_PROTOCOL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HEALTH_PORT}")"
  [[ "$status" == "500" ]]
}

@test "${HEALTH_ROUTE} does not log requests from ELB-HealthChecker User Agent" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -H 'Host: test.host' -A "ELB-HealthChecker/2.0" "http://localhost/${HEALTH_ROUTE}" > /dev/null 2>&1
  ! wait_for grep -i 'ELB-HealthChecker' "$NGINX_OUT"
}

@test "${HEALTH_ROUTE} conditionally can log requests from ELB-HealthChecker User Agent" {
  simulate_upstream
  SHOW_ELB_HEALTHCHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -H 'Host: test.host' -A "ELB-HealthChecker/2.0" "http://localhost/${HEALTH_ROUTE}" > /dev/null 2>&1
  wait_for grep -i 'ELB-HealthChecker' "$NGINX_OUT"
}

@test "${HEALTH_ROUTE} (HTTP): Nginx rewrites the request path to /healthcheck" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://localhost/${HEALTH_ROUTE}"
  wait_for grep 'GET /healthcheck' "$UPSTREAM_OUT"

  run grep -Fi '.aptible' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx discards headers" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs -H 'Authorization: foo' "http://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx sets X-Aptible-Health-Check" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs -H 'Authorization: foo' "http://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep -i 'X-Aptible-Health-Check' "$UPSTREAM_OUT"
}

@test "${HEALTH_ROUTE} (HTTP): Nginx rewrites the User-Agent header to Aptible Health Check" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs "http://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep 'Aptible Health Check' "$UPSTREAM_OUT"
  # TODO: grep -i curl! status 1
}

@test "${HEALTH_ROUTE} (HTTP): Nginx discards the request body" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs --data "foo=bar" "http://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx discards the request method" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fs -I "http://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'head' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx discards the response body" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl "http://localhost"
  [[ "$output" =~ "Hello World!" ]]

  run curl "http://localhost/${HEALTH_ROUTE}"
  [[ ! "$output" =~ "Hello World!" ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx returns a 502 if the upstream is not responding" {
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -sw "%{http_code}" "http://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 502 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx returns a 200 if the upstream is returning a 200" {
  UPSTREAM_RESPONSE="upstream-response.txt" simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -sw "%{http_code}" "http://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx returns a 200 if the upstream is returning a 500" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -sw "%{http_code}" "http://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx returns a 200 if FORCE_HEALTHCHECK_SUCCESS = true" {
  FORCE_HEALTHCHECK_SUCCESS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -sw "%{http_code}" "http://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx does not redirect even when FORCE_SSL is set" {
  simulate_upstream
  FORCE_SSL=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -sw "%{http_code}" "http://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx supports STRICT_HEALTH_CHECKS = true (200)" {
  simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "200" ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx supports STRICT_HEALTH_CHECKS = true (302)" {
  UPSTREAM_RESPONSE="upstream-response-302.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "302" ]]
}

@test "${HEALTH_ROUTE} (HTTP): Nginx supports STRICT_HEALTH_CHECKS = true (500)" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "500" ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx discards headers" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk -H 'Authorization: foo' "https://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx sets X-Aptible-Health-Check" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk "https://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep -i 'X-Aptible-Health-Check' "$UPSTREAM_OUT"
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx rewrites the User-Agent header to Aptible Health Check" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk "https://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  grep 'Aptible Health Check' "$UPSTREAM_OUT"
  # TODO: grep -i curl! status 1
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx discards the request body" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk --data "foo=bar" "https://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'foo' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx discards the request method" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk -I "https://localhost/${HEALTH_ROUTE}"
  wait_for grep -i 'get' "$UPSTREAM_OUT"

  run grep -i 'head' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx discards the response body" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -k "https://localhost"
  [[ "$output" =~ "Hello World!" ]]

  run curl -k "https://localhost/${HEALTH_ROUTE}"
  [[ ! "$output" =~ "Hello World!" ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx returns a 502 if the upstream is not responding" {
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -skw "%{http_code}" "https://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 502 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx returns a 200 if the upstream is returning a 200" {
  UPSTREAM_RESPONSE="upstream-response.txt" simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -skw "%{http_code}" "https://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx returns a 200 if the upstream is returning a 500" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -skw "%{http_code}" "https://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx returns a 200 if FORCE_HEALTHCHECK_SUCCESS = true" {
  FORCE_HEALTHCHECK_SUCCESS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run curl -o /dev/null -skw "%{http_code}" "https://localhost/${HEALTH_ROUTE}"
  [[ "$output" -eq 200 ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx supports STRICT_HEALTH_CHECKS = true (200)" {
  simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -k -s -o /dev/null -w "%{http_code}" "https://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "200" ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx supports STRICT_HEALTH_CHECKS = true (302)" {
  UPSTREAM_RESPONSE="upstream-response-302.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -k -s -o /dev/null -w "%{http_code}" "https://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "302" ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx supports STRICT_HEALTH_CHECKS = true (500)" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  status="$(curl -k -s -o /dev/null -w "%{http_code}" "https://localhost/${HEALTH_ROUTE}")"
  [[ "$status" == "500" ]]
}

@test "${HEALTH_ROUTE} (HTTPS): Nginx rewrites the request path to /healthcheck" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  curl -fsk "https://localhost/${HEALTH_ROUTE}"
  wait_for grep 'GET /healthcheck' "$UPSTREAM_OUT"

  run grep -Fi '.aptible' "$UPSTREAM_OUT"
  [[ "$status" -eq 1 ]]
}

@test "${HEALTH_ROUTE}: Nginx debounces health checks (200)" {
  simulate_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx

  # So... we can't use a pipe in our tests here, because that blows up in
  # Travis (it hangs forever doing nothing). This is an issue in BATS we've
  # encountered a number of times in the past. We work around the problem by
  # spawning a shell to run the pipe for us...
  url="http://localhost/${HEALTH_ROUTE}"
  sh -c "curl -fs '$url' | grep upstream:200"
  sh -c "curl -fs '$url' | grep cache:200"
  sh -c "curl -fs '$url' | grep cache:200"
  sh -c "curl -fs '$url' | grep cache:200"

  n="$(grep "GET /healthcheck" "$UPSTREAM_OUT" | wc -l)"
  [[ "$n" -eq 1 ]]
}

@test "${HEALTH_ROUTE}: Nginx debounces health checks (500, non strict)" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx

  url="http://localhost/${HEALTH_ROUTE}"
  sh -c "curl -fs '$url' | grep upstream:200"
  sh -c "curl -fs '$url' | grep cache:200"
  sh -c "curl -fs '$url' | grep cache:200"
  sh -c "curl -fs '$url' | grep cache:200"

  n="$(grep "GET /healthcheck" "$UPSTREAM_OUT" | wc -l)"
  [[ "$n" -eq 1 ]]
}

@test "${HEALTH_ROUTE}: Nginx debounces health checks (500, strict)" {
  UPSTREAM_RESPONSE="upstream-response-500.txt" simulate_upstream
  STRICT_HEALTH_CHECKS=true UPSTREAM_SERVERS=localhost:4000 wait_for_nginx

  url="http://localhost/${HEALTH_ROUTE}"
  sh -c "curl -s '$url' | grep upstream:500"
  sh -c "curl -s '$url' | grep cache:500"
  sh -c "curl -s '$url' | grep cache:500"
  sh -c "curl -s '$url' | grep cache:500"

  n="$(grep "GET /healthcheck" "$UPSTREAM_OUT" | wc -l)"
  [[ "$n" -eq 1 ]]
}

@test "${HEALTH_ROUTE}: Nginx debounces health checks with a slowish upstream" {
  UPSTREAM_DELAY=0.5 simulate_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}"

  n="$(grep "GET /healthcheck" "$UPSTREAM_OUT" | wc -l)"
  [[ "$n" -eq 1 ]]
}

@test "${HEALTH_ROUTE}: Nginx does not debounce health checks with a very slow upstream" {
  UPSTREAM_DELAY=3 simulate_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}" &
  sleep 0.1

  curl -fs "http://localhost/${HEALTH_ROUTE}"

  n="$(grep "GET /healthcheck" "$UPSTREAM_OUT" | wc -l)"
  [[ "$n" -eq 4 ]]
}

@test "it applies a default KEEPALIVE_TIMEOUT of 5 seconds (HTTP)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  # We're going to make 3 requests, but the last request will come in 8 seconds
  # after the second one. As a result, we should only see 2 requests on the
  # upstream.
  "${BATS_TEST_DIRNAME}/connect-keepalive" http 8

  # Ensure all the logs made it to $UPSTREAM_OUT
  curl -I localhost
  wait_for grep -i 'head' "$UPSTREAM_OUT"

  [[ "$(grep -i 'get' "$UPSTREAM_OUT" | wc -l)" -eq 2 ]]
}

@test "it applies a default KEEPALIVE_TIMEOUT of 5 seconds (HTTPS)" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  # Same as above
  "${BATS_TEST_DIRNAME}/connect-keepalive" https 8

  curl -I localhost
  wait_for grep -i 'head' "$UPSTREAM_OUT"

  [[ "$(grep -i 'get' "$UPSTREAM_OUT" | wc -l)" -eq 2 ]]
}

@test "it allows setting a custom KEEPALIVE_TIMEOUT (HTTP)" {
  simulate_upstream
  KEEPALIVE_TIMEOUT=60 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  # This time, we should see all 3 requests
  "${BATS_TEST_DIRNAME}/connect-keepalive" http 8

  curl -I localhost
  wait_for grep -i 'head' "$UPSTREAM_OUT"

  [[ "$(grep -i 'get' "$UPSTREAM_OUT" | wc -l)" -eq 3 ]]
}

@test "it allows setting a custom KEEPALIVE_TIMEOUT (HTTPS)" {
  simulate_upstream
  KEEPALIVE_TIMEOUT=60 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  # This time, we should see all 3 requests
  "${BATS_TEST_DIRNAME}/connect-keepalive" https 8

  curl -I localhost
  wait_for grep -i 'head' "$UPSTREAM_OUT"

  [[ "$(grep -i 'get' "$UPSTREAM_OUT" | wc -l)" -eq 3 ]]
}

@test "it ignores an invalid KEEPALIVE_TIMEOUT" {
  simulate_upstream
  KEEPALIVE_TIMEOUT="20+FOOBAR" UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  wait_for_proxy_protocol

  # Same as default test
  "${BATS_TEST_DIRNAME}/connect-keepalive" http 8

  curl -I localhost
  wait_for grep -i 'head' "$UPSTREAM_OUT"

  [[ "$(grep -i 'get' "$UPSTREAM_OUT" | wc -l)" -eq 2 ]]

  wait_for grep -i 'not acceptable' '/tmp/nginx.log'
}

@test "it allows setting a custom PROXY_IDLE_TIMEOUT (HTTP)" {
  UPSTREAM_DELAY=5 simulate_upstream
  PROXY_IDLE_TIMEOUT=1 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  return_code="$(curl -s -o /dev/null -w "%{http_code}" "http://localhost")"
  [[ "$return_code" == "502" ]] || [[ "$return_code" == "504" ]]
}

@test "it allows setting a custom PROXY_IDLE_TIMEOUT (HTTPS)" {
  UPSTREAM_DELAY=5 simulate_upstream
  PROXY_IDLE_TIMEOUT=1 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  return_code="$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost")"
  [[ "$return_code" == "502" ]] || [[ "$return_code" == "504" ]]
}

@test "it tolerates a slow upstream when PROXY_IDLE_TIMEOUT is set" {
  UPSTREAM_DELAY=5 simulate_upstream
  PROXY_IDLE_TIMEOUT=10 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "it tolerates a slow upstream when PROXY_IDLE_TIMEOUT is not set" {
  UPSTREAM_DELAY=5 simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It enables hostname filtering (HTTP)" {
  host=foobar
  HOSTNAME_FILTERING_SERVER_NAME="$host" wait_for_nginx
  curl --fail --connect-to "${host}:80:localhost:80" "http://${host}"
  ! curl --fail "http://localhost"
}

@test "It enables hostname filtering (HTTPS)" {
  host=foobar
  HOSTNAME_FILTERING_SERVER_NAME="$host" wait_for_nginx
  curl -k --fail --connect-to "${host}:443:localhost:443" "https://${host}"
  ! curl --fail "http://localhost"
}

@test "It should time out on slow body requests" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx

  run simulate_slow_body $BODY_DELAY

  [[ $output = "" ]]
  grep '"POST / HTTP/1.1" 408' "$NGINX_OUT"
}

@test "It should have a configurable client_body_timeout" {
  simulate_upstream
  UPSTREAM_SERVERS=127.0.0.1:4000 CLIENT_BODY_TIMEOUT=$(expr $BODY_DELAY + 1) wait_for_nginx

  run simulate_slow_body $BODY_DELAY

  grep 'HTTP/1.1 200' <<< "$output"
}

@test "It should not set Access-Control-Allow-Origin for proxied requests" {
  FORCE_SSL=true wait_for_nginx
  run curl -Ik https://localhost 2>/dev/null
  ! [[ "$output" =~ "Access-Control-Allow-Origin" ]]
}

@test "It should set Access-Control-Allow-Origin if we return an error on behalf of a failed upstream" {
  UPSTREAM_DELAY=5 simulate_upstream
  PROXY_IDLE_TIMEOUT=1 UPSTREAM_SERVERS=127.0.0.1:4000 wait_for_nginx
  run curl -Ik https://localhost 2>/dev/null
  [[ "$output" =~ "Access-Control-Allow-Origin" ]]
}
