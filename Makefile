export GO111MODULE=on

VERSION=$(shell git describe --tags --always --dirty)
SOURCE_DIRS = $(shell ls -d */ | grep -v vendor | grep -v build | grep -v .git | grep -v testdata | grep -v examples | grep -v third_party | grep -v .github | sed 's/\/$$//')

.PHONY: vendor vetcheck fmtcheck clean build gotest mod-clean

all: vetcheck fmtcheck build gotest mod-clean

# excluded from the default target because of fatal compilation error: fatal error: 'blst.h' file not found
vendor:
	go mod vendor

vetcheck:
	go vet ./...
	golangci-lint run -c .golangci.yml

fmtcheck:
	@gofmt -l -s $(SOURCE_DIRS) | grep ".*\.go"; if [ "$$?" = "0" ]; then exit 1; fi

clean:
	rm -r build/

build:
	@go build -o build/bin/native/cgotest ./cmd/cgotest

gotest:
	go test -cover -race -covermode=atomic ./...

mod-clean:
	go mod tidy
