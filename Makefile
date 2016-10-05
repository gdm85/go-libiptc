SRCFILES := *.go libip4tc/*.go libip6tc/*.go

all: build examples

build:
	go build
	cd libip4tc && go build
	cd libip6tc && go build

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
