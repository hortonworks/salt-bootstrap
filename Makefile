BINARY=salt-bootstrap

VERSION=0.3.0
BUILD_TIME=$(shell date +%FT%T)
LDFLAGS=-ldflags "-X github.com/sequenceiq/salt-bootstrap/saltboot.Version=${VERSION} -X github.com/sequenceiq/salt-bootstrap/saltboot.BuildTime=${BUILD_TIME}"

deps:
	go get github.com/gliderlabs/glu

build:
	GOOS=linux go build -a -installsuffix cgo ${LDFLAGS} -o build/Linux/${BINARY} main.go
	GOOS=darwin go build -a -installsuffix cgo ${LDFLAGS} -o build/Darwin/${BINARY} main.go

docker_env_up:
	docker-compose -f docker/docker-compose.yml up -d

docker_env_rm:
	docker-compose -f docker/docker-compose.yml stop -t 0
	docker-compose -f docker/docker-compose.yml rm --all -f

release: build
	rm -rf release
	glu release

.PHONY: build
