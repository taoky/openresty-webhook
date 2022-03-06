FROM openresty/openresty:alpine

RUN apk update && apk add git --no-cache

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off; env GITHUB_WEBHOOK_SECRET; user root; worker_processes 4;"]
