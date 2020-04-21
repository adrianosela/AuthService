NAME:=$(shell basename `git rev-parse --show-toplevel`)
HASH:=$(shell git rev-parse --verify --short HEAD)

all: build

clean:
	rm -rf pkg bin

deploy: dockerbuild down
	docker run -d --name $(NAME)-container -p 8888:8888 $(NAME)-image

up: build
	./$(NAME)

dockerbuild: vet
	GOOS=linux GOARCH=amd64 go build -a -o $(NAME)
	docker build -t $(NAME)-image .

build: dep
	go build -o $(NAME)

dep:
	 go get -v

down:
	(docker stop $(NAME)-container || true) && (docker rm $(NAME)-container || true)
