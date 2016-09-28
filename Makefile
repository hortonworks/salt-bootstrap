BINARY=salt-bootstrap

VERSION=0.9.0
BUILD_TIME=$(shell date +%FT%T)
LDFLAGS=-ldflags "-X github.com/hortonworks/salt-bootstrap/saltboot.Version=${VERSION} -X github.com/hortonworks/salt-bootstrap/saltboot.BuildTime=${BUILD_TIME}"
GOFILES = $(shell find . -type f -name '*.go')


deps:
	go get github.com/gliderlabs/glu
	go get github.com/tools/godep

clean:
	rm -rf build

all: build
	
format:
	@gofmt -w ${GOFILES}

test:
	go test ./...

build: format test build-darwin build-linux

build-darwin:
	GOOS=darwin go build -a -installsuffix cgo ${LDFLAGS} -o build/Darwin/${BINARY} main.go

build-linux:
	GOOS=linux go build -a -installsuffix cgo ${LDFLAGS} -o build/Linux/${BINARY} main.go

release: build
	rm -rf release
	glu release

docker_env_up:
	docker-compose -f docker/docker-compose.yml up -d

docker_env_rm:
	docker-compose -f docker/docker-compose.yml stop -t 0
	docker-compose -f docker/docker-compose.yml rm --all -f

.PHONY: build
