EFAULT_GOAL := build 
.PHONY: help build test 

build: ## Build SSRFUZZ Binary 
	@go build


all: build

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
