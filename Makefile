.PHONY: build docker-build

all: build

build:
	go build

docker-build: build
	docker build -t flex/auth_service -f Dockerfile .
