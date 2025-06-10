ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

# GO_BIN=/Users/konstantingasser/coffeecode/uni/golangech/bin/go
GO_BIN=$(shell which go)

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: zgrab2

.PHONY: all clean integration-test integration-test-clean docker-runner gofmt test test-ech build-linux

# Test currently only runs on the modules folder because some of the 
# third-party libraries in lib (e.g. http) are failing.
test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

lint:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/.template/")

BUILD_NAME=zgrab2
BUILD_NAME_LINUX=zgrab2-linux

build-linux: $(GO_FILES)
	cd cmd/zgrab2 && GOOS=linux GOARCH=amd64 $(GO_BIN) build -o $(BUILD_NAME_LINUX) && cd ../..
	rm -f $(BUILD_NAME_LINUX)
	ln -s cmd/zgrab2/$(BUILD_NAME_LINUX)$(EXECUTABLE_EXTENSION) $(BUILD_NAME_LINUX)

build: $(GO_FILES)
	cd cmd/zgrab2 && $(GO_BIN) build -o $(BUILD_NAME) && cd ../..
	rm -f $(BUILD_NAME)
	ln -s cmd/zgrab2/$(BUILD_NAME)$(EXECUTABLE_EXTENSION) $(BUILD_NAME)


HOST=ech.research.netd.cs.tu-dresden.de
PATH=/mnt/data01/ech-scanner/build
deploy: build-linux
	scp $(BUILD_NAME_LINUX) $(USER)@$(HOST):$(PATH)

clean:
	cd cmd/zgrab2 && go clean
	rm -f $(BUILD_NAME) $(BUILD_NAME_LINUX)
