#!/usr/bin/env bats

install_heartbleed() {
  export GOPATH=/tmp/gocode
  export PATH=${PATH}:/usr/local/go/bin:${GOPATH}/bin
  go get github.com/FiloSottile/Heartbleed
  go install github.com/FiloSottile/Heartbleed
}

uninstall_heartbleed() {
  rm -rf ${GOPATH}
}

wait_for_nginx() {
  /usr/local/bin/nginx-wrapper > /tmp/nginx.log &
  while ! pgrep -x "nginx: worker process" > /dev/null ; do sleep 0.1; done
}

wait_for_proxy_protocol() {
  # This is really weird, but it appears NGiNX takes several seconds to
  # correctly handle Proxy Protocol requests
  haproxy -f ${BATS_TEST_DIRNAME}/haproxy.cfg
  while ! curl localhost:8080 &> /dev/null ; do sleep 0.1 ; done
}

local_s_client() {
  echo OK | openssl s_client -connect localhost:443 $@
}

simulate_http_upstream() {
  "$BATS_TEST_DIRNAME"/upstream-server \
    "$BATS_TEST_DIRNAME"/upstream-http-response.txt &
}

simulate_tcp_upstream() {
  "$BATS_TEST_DIRNAME"/upstream-server \
    "$BATS_TEST_DIRNAME"/upstream-tcp-response.txt &
}

setup() {
  TMPDIR=$(mktemp -d)
  cp /usr/html/* "$TMPDIR"
}

teardown() {
  pkill nginx-wrapper || true
  pkill nginx || true
  pkill -f upstream-server || true
  pkill nc || true
  pkill haproxy || true
  rm -rf /etc/nginx/ssl/*
  rm -f /etc/nginx/sites-enabled/http.conf
  rm -f /etc/nginx/conf.d/tcp.conf
  cp "$TMPDIR"/* /usr/html
}

@test "It should install NGiNX 1.9.2" {
  run /usr/sbin/nginx -v
  [[ "$output" =~ "1.9.2"  ]]
}

@test "It should pass an external Heartbleed test" {
  skip
  install_heartbleed
  wait_for_nginx
  Heartbleed localhost:443
  uninstall_heartbleed
}

@test "It should accept large file uploads" {
  dd if=/dev/zero of=zeros.bin count=1024 bs=4096
  wait_for_nginx
  run curl -k --form upload=@zeros.bin --form press=OK https://localhost:443/
  [ "$status" -eq "0" ]
  [[ ! "$output" =~ "413"  ]]
}

@test "It should log to STDOUT" {
  wait_for_nginx
  curl localhost > /dev/null 2>&1
  [[ -s /tmp/nginx.log ]]
}

@test "It should log to STDOUT (Proxy Protocol)" {
  PROXY_PROTOCOL=true wait_for_nginx
  wait_for_proxy_protocol
  curl localhost:8080 > /dev/null 2>&1
  [[ -s /tmp/nginx.log ]]
}

@test "It should accept and configure a MAINTENANCE_PAGE_URL" {
  UPSTREAM_SERVERS=localhost:4000 \
    MAINTENANCE_PAGE_URL=https://www.aptible.com/404.html wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "@aptiblestatus" ]]
}

@test "It should accept a list of UPSTREAM_SERVERS" {
  simulate_http_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  run curl localhost 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should accept a list of UPSTREAM_SERVERS (Proxy Protocol)" {
  simulate_http_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  wait_for_proxy_protocol
  run curl localhost:8080 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should work with PROTOCOL=tcp" {
  simulate_tcp_upstream
  PROTOCOL=tcp UPSTREAM_SERVER_PORTS=9000 UPSTREAM_SERVERS_9000=localhost:4000 wait_for_nginx
  run nc localhost 9000 2>&1

  # There should be no errors in the NGiNX log file
  [ ! -s /tmp/nginx.log ]

  # For some reason, nc ONLY generates output when run with a TTY (i.e.,
  # docker run -t). So the following will cause the test to fail in a
  # `docker build` context, even though it succeeds when run with a TTY
  # [[ "$output" =~ "TCP OK" ]]
}

@test "It should handle HTTPS over Proxy Protocol" {
  simulate_http_upstream
  PROXY_PROTOCOL=true UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  wait_for_proxy_protocol
  run curl -k https://localhost:8443 2>/dev/null
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

@test "It allows underscores in headers" {
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
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

@test "It sets an X-Request-Start header" {
  # https://docs.newrelic.com/docs/apm/applications-menu/features/request-queue-server-configuration-examples#nginx
  rm /tmp/nc.log || true
  nc -l -p 4000 127.0.0.1 > /tmp/nc.log &
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  curl --max-time 1 http://localhost
  run cat /tmp/nc.log
  [[ "$output" =~ "X-Request-Start: t=" ]]
}

@test "It supports GZIP compression of responses" {
  simulate_http_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  curl -H "Accept-Encoding: gzip" localhost | gunzip -c | grep "Hello World!"
}
