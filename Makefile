SRCFILES := *.go ipv4/*.go ipv6/*.go

all: build examples

build:
	cd ipv4 && go build
	cd ipv6 && go build

test:
	go test

examples: examples/dump-table-raw/dump-table-raw examples/dump-table-rules/dump-table-rules examples/lock/lock

examples/dump-table-raw/dump-table-raw: examples/dump-table-raw/dump-table-raw.go $(SRCFILES)
	cd examples/dump-table-raw && go build

examples/dump-table-rules/dump-table-rules: examples/dump-table-rules/dump-table-rules.go $(SRCFILES)
	cd examples/dump-table-rules && go build

examples/lock/lock: examples/lock/lock.go $(SRCFILES)
	cd examples/lock && go build

clean:
	rm -f examples/dump-table-raw/dump-table-raw examples/dump-table-rules/dump-table-rules examples/lock/lock

.PHONY: all build test examples clean
