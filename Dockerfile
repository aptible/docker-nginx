FROM quay.io/aptible/ubuntu:12.10

RUN apt-get -y install nginx && echo "daemon off;" >> /etc/nginx/nginx.conf

EXPOSE 443 80

CMD /usr/sbin/nginx -c /etc/nginx/nginx.conf
