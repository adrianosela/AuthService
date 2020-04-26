all: build

clean:
	rm -rf pkg bin

build:  dep
	go build -o jwt
	cp ./jwt /usr/local/bin

dep:
	 go get -v
