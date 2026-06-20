.PHONY: build-linux build-windows build-mac build-arm build-all clean

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/phantom-linux .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/phantom-windows.exe .

build-mac:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/phantom-macos .

build-arm:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bin/phantom-arm64 .

build-all: build-linux build-windows build-mac build-arm

clean:
	rm -rf bin/
