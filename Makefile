build: build-filter build-updater
build-rust: build-rust-filter build-rust-updater

build-filter:
	@echo "Building filter..."
	cd filter && GOOS=wasip1 GOARCH=wasm tinygo build -buildmode=c-shared -o filter.wasm .



build-updater:
	@echo "Building updater..."
	cd updater && GOOS=wasip1 GOARCH=wasm tinygo build -target=wasip1 -buildmode=c-shared -o updater.wasm .


build-rust-filter:
	@echo "Building rust filter..."
	cd rust_filter && cargo build --target wasm32-wasip1



build-rust-updater:
	@echo "Building rust updater..."
	cd rust_updater && cargo build --target wasm32-wasip1



