FROM alpine:3.5

RUN apk add --update bash curl && rm -rf /var/cache/apk/*

ADD AuthService /bin/AuthService

EXPOSE 8888

CMD ["/bin/AuthService"]
