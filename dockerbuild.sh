#!/bin/bash +x

GOOS=linux GOARCH=amd64 go build -a -o AuthService

docker build -t authservice .

