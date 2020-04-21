all: build

clean:
	rm -rf pkg bin

build:  vet
	go build -o jwt
	cp ./jwt /usr/local/bin

vet: dependencies
	 go vet -x

dependencies:
	 go get -v
