
all:
	go build github.com/cofyc/authproxy/cmd/authproxy

linux:
	GOOS=linux GOARCH=amd64 go build github.com/cofyc/authproxy/cmd/authproxy

test:
	go test github.com/cofyc/authproxy/...

style:
	@echo ">> checking code style"
	@! gofmt -d $(shell find . -path "*vendor*" -prune -o -name '*.go' -print) | grep '^'
