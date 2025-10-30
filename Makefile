.PHONY: all build clean
all: build
build:
	go build -o bin/analyzer ./cmd
	cp -r data bin/data
	cp .env bin/.env
	rm -rf bin/data/table.sql
clean:
	rm -rf bin/*
