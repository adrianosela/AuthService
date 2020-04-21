NAME:=$(shell basename `git rev-parse --show-toplevel`)
HASH:=$(shell git rev-parse --verify --short HEAD)

all: build

clean:
	rm -rf pkg bin

up: dockerbuild
	docker-compose up

dockerbuild: dep 
	GOOS=linux GOARCH=amd64 go build -a -o $(NAME)
	docker build -t $(NAME)-image .

build: dep
	go build -o $(NAME)

dep:
	 go get -v

down:
	(docker stop $(NAME)-container || true) && (docker rm $(NAME)-container || true)
