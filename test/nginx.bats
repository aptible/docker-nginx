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
  while ! pgrep -x nginx > /dev/null ; do sleep 0.1; done
}

wait_for_proxy_protocol() {
  # This is really weird, but it appears NGiNX takes several seconds to
  # correctly handle Proxy Protocol requests
  while ! curl localhost:8080 &> /dev/null ; do sleep 0.1 ; done
}

local_s_client() {
  echo OK | openssl s_client -connect localhost:8443 $@
}

simulate_upstream() {
  # `sleep 0.5` is necessary to avoid the following NGiNX error:
  # readv() failed (104: Connection reset by peer) while reading upstream
  cmd="cat ${BATS_TEST_DIRNAME}/upstream-response.txt && sleep 0.5"
  tcpserver 127.0.0.1 4000 sh -c "$cmd" &
}

setup() {
  # Launch HAProxy to simulate Proxy Protocol requests
  haproxy -f ${BATS_TEST_DIRNAME}/haproxy.cfg
}

teardown() {
  pkill nginx-wrapper || true
  pkill nginx || true
  pkill tcpserver || true
  pkill haproxy || true
  rm -rf /etc/nginx/ssl/*
}

@test "It should install NGiNX 1.6.2" {
  run /usr/sbin/nginx -v
  [[ "$output" =~ "1.6.2"  ]]
}

@test "It should pass an external Heartbleed test" {
  install_heartbleed
  wait_for_nginx
  wait_for_proxy_protocol
  Heartbleed localhost:8443
  uninstall_heartbleed
}

@test "It should accept large file uploads" {
  dd if=/dev/zero of=zeros.bin count=1024 bs=4096
  wait_for_nginx
  wait_for_proxy_protocol
  run curl -k --form upload=@zeros.bin --form press=OK https://localhost:8443/
  [ "$status" -eq "0" ]
  [[ ! "$output" =~ "413"  ]]
}

@test "It should log to STDOUT" {
  wait_for_nginx
  wait_for_proxy_protocol
  curl localhost:8080 > /dev/null 2>&1
  [[ -s /tmp/nginx.log ]]
}

@test "It should accept and configure a MAINTENANCE_PAGE_URL" {
  skip
}

@test "It should accept a list of UPSTREAM_SERVERS" {
  simulate_upstream
  UPSTREAM_SERVERS=localhost:4000 wait_for_nginx
  wait_for_proxy_protocol
  wait_for_proxy_protocol
  run curl localhost:8080 2>/dev/null
  [[ "$output" =~ "Hello World!" ]]
}

@test "It should honor FORCE_SSL" {
  FORCE_SSL=true wait_for_nginx
  wait_for_proxy_protocol
  run curl -I localhost:8080 2>/dev/null
  [[ "$output" =~ "HTTP/1.1 301 Moved Permanently" ]]
  [[ "$output" =~ "Location: https://localhost" ]]
}

@test "It should send a Strict-Transport-Security header with FORCE_SSL" {
  FORCE_SSL=true wait_for_nginx
  wait_for_proxy_protocol
  run curl -Ik https://localhost:8443 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security: max-age=31536000" ]]
}

@test "The Strict-Transport-Security header's max-age should be configurable" {
  FORCE_SSL=true HSTS_MAX_AGE=1234 wait_for_nginx
  wait_for_proxy_protocol
  run curl -Ik https://localhost:8443 2>/dev/null
  [[ "$output" =~ "Strict-Transport-Security: max-age=1234" ]]
}

@test "Its OpenSSL client should support TLS_FALLBACK_SCSV" {
  FORCE_SSL=true wait_for_nginx
  wait_for_proxy_protocol
  run local_s_client -fallback_scsv
  [ "$status" -eq "0" ]
}

@test "It should support TLS_FALLBACK_SCSV by default" {
  FORCE_SSL=true wait_for_nginx
  wait_for_proxy_protocol
  run local_s_client -fallback_scsv -no_tls1_2
  [ "$status" -ne "0" ]
  [[ "$output" =~ "inappropriate fallback" ]]
}
