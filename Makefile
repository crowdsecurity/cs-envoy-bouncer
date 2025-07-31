BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIMESTAMP ?= $(shell date +%Y-%m-%d_%H:%M:%S)
RUST_TARGET = wasm32-wasip1

.PHONY: all
all: clean build

.PHONY: build
build: build-filter build-updater

.PHONY: build-filter
build-filter:
	@echo "Building filter..."
	cd rust_filter && cargo build --target $(RUST_TARGET) --release

.PHONY: build-updater
build-updater:
	@echo "Building updater..."
	cd rust_updater && cargo build --target $(RUST_TARGET) --release

.PHONY: test
test:
	@echo "Tests disabled for proxy-wasm modules (require runtime environment)"
	@echo "Run individual module tests manually if needed:"
	@echo "  cd rust_filter && cargo test config::tests"
	@echo "  cd rust_updater && cargo test config::tests"

.PHONY: clean
clean:
	@echo "Cleaning..."
	cd rust_filter && cargo clean
	cd rust_updater && cargo clean
	rm -f *.tar.gz

.PHONY: tarball
tarball: build
	@echo "Creating release tarball..."
	@mkdir -p crowdsec-envoy-bouncer-$(BUILD_VERSION)
	@cp rust_filter/target/$(RUST_TARGET)/release/crowdsec_filter.wasm crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@cp rust_updater/target/$(RUST_TARGET)/release/crowdsec_updater.wasm crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@cp -r example crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@cp README.md crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@tar czf crowdsec-envoy-bouncer-$(BUILD_VERSION).tar.gz crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@rm -rf crowdsec-envoy-bouncer-$(BUILD_VERSION)/
	@echo "Tarball created: crowdsec-envoy-bouncer-$(BUILD_VERSION).tar.gz"

.PHONY: lint
lint:
	@echo "Running lint..."
	cd rust_filter && cargo clippy -- -D warnings
	cd rust_updater && cargo clippy -- -D warnings

.PHONY: vendor
vendor:
	@echo "Vendoring dependencies..."
	cd rust_filter && cargo vendor
	cd rust_updater && cargo vendor

.PHONY: setup
setup:
	@echo "Setting up build environment..."
	rustup target add $(RUST_TARGET)
	rustup component add clippy rustfmt

.PHONY: release
release: clean lint build tarball

.PHONY: help
help:
	@echo "CrowdSec Envoy Bouncer - $(BUILD_VERSION)"
	@echo ""
	@echo "Usage:"
	@echo "  make all       - Clean, build and test"
	@echo "  make build     - Build WASM modules"
	@echo "  make test      - Run tests"
	@echo "  make lint      - Run linter"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make tarball   - Create release tarball"
	@echo "  make release   - Full release process"
	@echo "  make setup     - Setup build environment"
	@echo ""