FROM quay.io/aptible/ubuntu:14.04

# Install NGiNX from source
RUN apt-get update
RUN apt-get -y install software-properties-common \
      python-software-properties && \
    add-apt-repository -y ppa:nginx/stable && apt-get update && \
    apt-get -y install nginx && mkdir -p /etc/nginx/ssl

# Install Ruby (necessary for ERB templating)
RUN apt-get -y install ruby

# Install Go (necessary for Heartbleed test)
RUN apt-get -y install wget && cd /tmp && \
    wget https://go.googlecode.com/files/go1.2.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.2.1.linux-amd64.tar.gz

# Install tcpserver for tests
RUN apt-get -y install ucspi-tcp

# Install cURL (necessary for integration tests)
RUN apt-get -y install curl

# Install HAProxy (necessary for Proxy Protocol integration tests)
RUN add-apt-repository ppa:vbernat/haproxy-1.5
RUN apt-get update && apt-get -y install haproxy

ADD templates/etc /etc
ADD templates/bin /usr/local/bin

ADD test /tmp/test
RUN bats /tmp/test

# Uninstall Go
RUN rm -rf /tmp/go1.2.1.linux-amd64.tar.gz /usr/local/go

# Uninstall haproxy
RUN apt-get -y remove haproxy

VOLUME /etc/nginx/ssl

EXPOSE 80 443

CMD ["/usr/local/bin/nginx-wrapper"]
