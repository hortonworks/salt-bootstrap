BINARY=salt-bootstrap

VERSION=0.14.2
BUILD_TIME=$(shell date +%FT%T)
LDFLAGS=-ldflags "-X github.com/hortonworks/salt-bootstrap/saltboot.Version=${VERSION} -X github.com/hortonworks/salt-bootstrap/saltboot.BuildTime=${BUILD_TIME}"
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./.git/*")

deps:
ifeq (, $(shell which gh))
ifeq ($(shell uname),Linux)
	apt-get update
	apt-get -y install software-properties-common
	apt-key adv --keyserver keyserver.ubuntu.com --recv-key C99B11DEB97541F0
	apt-add-repository https://cli.github.com/packages
	apt update
	apt -y install gh
endif
ifeq ($(shell uname),Darwin)
	brew install gh
endif
	gh auth login
endif
	go get -u github.com/golang/dep/cmd/dep

clean:
	rm -rf build

all: build
	
_check: formatcheck vet

formatcheck:
	([ -z "$(shell gofmt -d $(GOFILES_NOVENDOR))" ]) || (echo "Source is unformatted"; exit 1)

format:
	@gofmt -w ${GOFILES_NOVENDOR}

vet:
	go vet ./...

test:
	go test -timeout 30s -coverprofile coverage -race $$(go list ./... | grep -v /vendor/)

_build: build-darwin build-linux build-ppc64le build-linux-arm64

build: _check test _build

build-docker:
	@#USER_NS='-u $(shell id -u $(whoami)):$(shell id -g $(whoami))'
	docker run --rm ${USER_NS} -v "${PWD}":/go/src/github.com/hortonworks/salt-bootstrap -w /go/src/github.com/hortonworks/salt-bootstrap -e VERSION=${VERSION} golang:1.14.3 make build

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -a -installsuffix cgo ${LDFLAGS} -o build/Darwin_x86_64/${BINARY} main.go

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -a -installsuffix cgo ${LDFLAGS} -o build/Darwin_arm64/${BINARY} main.go

build-linux:
	GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo ${LDFLAGS} -o build/Linux_x86_64/${BINARY} main.go

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo ${LDFLAGS} -o build/Linux_arm64/${BINARY} main.go

build-ppc64le:
	GOOS=linux GOARCH=ppc64le go build -a -installsuffix cgo ${LDFLAGS} -o build/Linux_ppc64le/${BINARY} main.go

release: build-docker
	VERSION=${VERSION} BINARY=${BINARY} ./release.sh

docker_env_up:
	docker-compose -f docker/docker-compose.yml up -d

docker_env_rm:
	docker-compose -f docker/docker-compose.yml stop -t 0
	docker-compose -f docker/docker-compose.yml rm --all -f

.DEFAULT_GOAL := build

.PHONY: build
