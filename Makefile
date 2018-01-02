BINARY=salt-bootstrap

VERSION=0.12.0
BUILD_TIME=$(shell date +%FT%T)
LDFLAGS=-ldflags "-X github.com/hortonworks/salt-bootstrap/saltboot.Version=${VERSION} -X github.com/hortonworks/salt-bootstrap/saltboot.BuildTime=${BUILD_TIME}"
GOFILES = $(shell find . -type f -name '*.go')


deps: deps-errcheck
	go get github.com/gliderlabs/glu
	go get -u github.com/golang/dep/cmd/dep

deps-errcheck:
	go get -u github.com/kisielk/errcheck

clean:
	rm -rf build

all: build
	
format:
	@gofmt -w ${GOFILES}

vet:
	go vet ./...

test:
	go test -timeout 10s -race ./...

errcheck:
	errcheck -ignoretests ./...

build: errcheck format vet test build-darwin build-linux

build-docker:
	@#USER_NS='-u $(shell id -u $(whoami)):$(shell id -g $(whoami))'
	docker run --rm ${USER_NS} -v "${PWD}":/go/src/github.com/hortonworks/salt-bootstrap -w /go/src/github.com/hortonworks/salt-bootstrap -e VERSION=${VERSION} golang:1.9.2 make deps-errcheck build

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

.DEFAULT_GOAL := build

.PHONY: build
