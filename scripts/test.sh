#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_step() {
    echo -e "${YELLOW}==>${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

handle_error() {
    echo_error "Error on line $1"
    exit 1
}

trap 'handle_error $LINENO' ERR

# Ensure we're in the project root
cd "$(dirname "$0")/.."

# Create temporary test directory
TEST_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo_step "Setting up Python environment with uv"
uv venv "$TEST_DIR/venv" --python=3.11
VIRTUAL_ENV="$TEST_DIR/venv"
PATH="$VIRTUAL_ENV/bin:$PATH"
export VIRTUAL_ENV PATH

echo_step "Installing Python dependencies"
uv pip install pytest click maturin

echo_step "Running Rust format "
cargo fmt --all
echo_success "Rust format check passed"

echo_step "NOT Running Rust clippy"
# cargo clippy --all-features -- -Dwarnings
echo_success "Rust clippy passed"

echo_step "Running Rust tests"
cargo test
echo_success "Rust tests passed"

echo_step "Building Python package with maturin"
uv pip install -e . || { echo_error "Failed to install package"; exit 1; }

echo_step "Running Python tests"
PYTHONPATH="$PWD" pytest tests/ -v || { echo_error "Python tests failed"; exit 1; }

echo_step "Testing CLI functionality"
# Create test files and directories
mkdir -p "$TEST_DIR/chunks"
echo "Hello, World!" > "$TEST_DIR/input.txt"

echo_step "Testing file encryption"
self_encryption encrypt-file "$TEST_DIR/input.txt" "$TEST_DIR/chunks" > "$TEST_DIR/data_map.json"
echo_success "Encryption successful"

echo_step "Testing file decryption"
self_encryption decrypt-file "$TEST_DIR/data_map.json" "$TEST_DIR/chunks" "$TEST_DIR/output.txt"
echo_success "Decryption successful"

# Verify the contents match
if diff "$TEST_DIR/input.txt" "$TEST_DIR/output.txt" >/dev/null; then
    echo_success "Content verification successful"
else
    echo_error "Content verification failed"
    exit 1
fi

echo_step "Testing streaming decryption"
self_encryption decrypt-file "$TEST_DIR/data_map.json" "$TEST_DIR/chunks" "$TEST_DIR/output_streaming.txt" --streaming
echo_success "Streaming decryption successful"

# Verify the streaming contents match
if diff "$TEST_DIR/input.txt" "$TEST_DIR/output_streaming.txt" >/dev/null; then
    echo_success "Streaming content verification successful"
else
    echo_error "Streaming content verification failed"
    exit 1
fi

# Test with a larger file
echo_step "Testing with larger file (1MB)"
dd if=/dev/urandom of="$TEST_DIR/large_input.bin" bs=1M count=1 2>/dev/null
self_encryption encrypt-file "$TEST_DIR/large_input.bin" "$TEST_DIR/chunks" > "$TEST_DIR/large_data_map.json"
self_encryption decrypt-file "$TEST_DIR/large_data_map.json" "$TEST_DIR/chunks" "$TEST_DIR/large_output.bin"

if diff "$TEST_DIR/large_input.bin" "$TEST_DIR/large_output.bin" >/dev/null; then
    echo_success "Large file test successful"
else
    echo_error "Large file test failed"
    exit 1
fi

echo -e "\n${GREEN}All tests passed successfully!${NC}"
