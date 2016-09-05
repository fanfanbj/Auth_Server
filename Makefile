.PHONY: deps build docker-build

all: build

deps:
	@GOPATH=`pwd` go get -t -v ./...

build: 
	@GOPATH=`pwd` go build -o ./bin/flex-auth-service

docker-build: build
	docker build -t flex/auth_service -f Dockerfile .
