BINARY := sipreaper
PKG := github.com/andycol/sipreaper
VERSION := 0.1.0

.PHONY: build test clean

build:
	go build -o $(BINARY) ./cmd/sipreaper

test:
	go test ./... -v -race

clean:
	rm -f $(BINARY)
