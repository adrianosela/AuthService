FROM alpine:3.5

RUN apk add --update bash curl && rm -rf /var/cache/apk/*

ADD auth /bin/auth

EXPOSE 80
EXPOSE 443

CMD ["/bin/auth"]
