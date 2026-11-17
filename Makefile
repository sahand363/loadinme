APP=loadinme
GO?=go

build:
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) build -o $(APP) .

install: build
	install -m 755 $(APP) $(HOME)/.local/bin/$(APP)

run:
	./$(APP) serve --port 8080

menu:
	./$(APP) menu

test:
	$(GO) test -v ./...

clean:
	rm -f $(APP) loadinme-linux-amd64 loadinme-linux-arm64 loadinme-windows-amd64.exe
