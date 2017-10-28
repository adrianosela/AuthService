all: build

clean:
	rm -rf pkg bin

deploy: dockerbuild down
	docker run -d --name authentication_service -p 8888:8888 authservice

up: build
	./AuthService

dockerbuild:
	./dockerbuild.sh

build:
	go build -o ./AuthService

down:
	(docker stop authentication_service || true) && (docker rm authentication_service || true)
