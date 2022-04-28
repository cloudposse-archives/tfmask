SHELL = /bin/bash

PATH:=$(PATH):$(GOPATH)/bin

-include $(shell curl -sSL -o .build-harness "https://cloudposse.tools/build-harness"; echo .build-harness)

build: go/build
	@exit 0

