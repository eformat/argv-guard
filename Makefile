# argv-guard — LD_PRELOAD execve veto
# Convention: the assistant scaffolds and edits; the human owns git (init + commits).

LIB     := target/release/libargvguard.so
DESTDIR ?=
PREFIX  ?= $(HOME)/.local

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --release

.PHONY: debug
debug:
	cargo build

.PHONY: test
test: build
	cargo test --release
	./test/integration.sh

.PHONY: clippy
clippy:
	cargo clippy --release -- -D warnings

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: install
install: build
	@mkdir -p $(DESTDIR)$(PREFIX)/lib/argv-guard
	cp -f $(LIB) $(DESTDIR)$(PREFIX)/lib/argv-guard/libargvguard.so
	@echo "installed: $(DESTDIR)$(PREFIX)/lib/argv-guard/libargvguard.so"
	@echo "arm:"
	@echo '  export LD_PRELOAD="$(DESTDIR)$(PREFIX)/lib/argv-guard/libargvguard.so$${LD_PRELOAD:+:$$LD_PRELOAD}"'
	@echo "bypass: ARVGUARD_OFF=1 <command>"
	@echo 'NOTE: arming affects NEW processes only — run "exec bash" or open a new'
	@echo 'terminal before testing; self-test: bash -c "/bin/true Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWX"'

.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/lib/argv-guard
	@echo "removed: $(DESTDIR)$(PREFIX)/lib/argv-guard (drop the export line from your rc)"

.PHONY: clean
clean:
	cargo clean
