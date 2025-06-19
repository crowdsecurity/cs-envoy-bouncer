build: build-filter build-updater

build-filter:
	@echo "Building filter..."
	cd filter && GOOS=wasip1 GOARCH=wasm tinygo build -buildmode=c-shared -o filter.wasm .



build-updater:
	@echo "Building updater..."
	cd updater && GOOS=wasip1 GOARCH=wasm tinygo build -target=wasip1 -buildmode=c-shared -o updater.wasm .



