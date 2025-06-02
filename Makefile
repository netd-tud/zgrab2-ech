ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_BIN=/Users/konstantingasser/coffeecode/uni/golangech/bin/go
GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: zgrab2

.PHONY: all clean integration-test integration-test-clean docker-runner gofmt test test-ech build-linux

# Test currently only runs on the modules folder because some of the 
# third-party libraries in lib (e.g. http) are failing.
test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

test-ech:
	cd modules/ech && $(GO_BIN) test -v ./...

lint:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/.template/")

zgrab2: $(GO_FILES)
	cd cmd/zgrab2 && $(GO_BIN) build && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

build-linux: $(GO_FILES)
	cd cmd/zgrab2 && GOOS=linux GOARCH=amd64 $(GO_BIN) build -o zgrab2-linux && cd ../..
	rm -f zgrab2-linux
	ln -s cmd/zgrab2/zgrab2-linux$(EXECUTABLE_EXTENSION) zgrab2-linux

BUILD_NAME=zgrab2-linux-greased
build-linux-greased: $(GO_FILES)
	cd cmd/zgrab2 && GOOS=linux GOARCH=amd64 $(GO_BIN) build -o $(BUILD_NAME) && cd ../..
	rm -f zgrab2-linux
	ln -s cmd/zgrab2/$(BUILD_NAME)$(EXECUTABLE_EXTENSION) $(BUILD_NAME)

build: $(GO_FILES)
	cd cmd/zgrab2 && $(GO_BIN) build -o zgrab2 && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

docker-runner: clean
	make -C docker-runner

integration-test: docker-runner
	rm -rf zgrab-output
	TEST_MODULES=$(TEST_MODULES) ./integration_tests/test.sh

integration-test-clean:
	rm -rf zgrab-output
	./integration_tests/cleanup.sh
	make -C docker-runner clean

clean:
	cd cmd/zgrab2 && go clean
	rm -f zgrab2 zgrab2-*

