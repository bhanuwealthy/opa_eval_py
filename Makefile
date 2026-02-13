VENV := .venv
PY   := $(VENV)/bin/python3

.PHONY: build release test bench clean venv

venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -r requirements.txt

release: venv
	$(VENV)/bin/maturin build --release # darwin platform
	@echo "-----Apple built----"
	$(VENV)/bin/maturin build --release --target x86_64-unknown-linux-gnu --zig --compatibility manylinux2014 # linux
	@echo "-----AnyLinux built----"
	$(VENV)/bin/maturin build --release --target x86_64-pc-windows-msvc # windows
	@echo "-----Windows built----"

build: #venv
	$(VENV)/bin/maturin develop --release

test: build
	$(PY) -m pytest tests/ -v

bench: build
	$(PY) -m pytest tests/test_bench.py -v

clean:
	cargo clean
	rm -rf target/
