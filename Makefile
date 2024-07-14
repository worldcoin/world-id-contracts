# By default we want to build.
all: install build

# ===== Basic Development Rules =======================================================================================

# Install forge dependencies (not needed if submodules are already initialized).
install:; forge install

# Build contracts.
build:; forge build

# Run tests, with debug information and gas reports.
test:; FOUNDRY_PROFILE=debug forge test

# Clean the solidity build directory.
clean:; forge clean; rm -rf out/

# Get the contract sizes.
sizes:; forge build --sizes 2>&1 > .size-snapshot

# ===== Profiling Rules ===============================================================================================

# Benchmark the tests.
bench:; forge test --gas-report --no-match-test testCannotRegisterIfProofIncorrect

# Snapshot the current test usages.
snapshot:; forge snapshot --no-match-test testCannotRegisterIfProofIncorrect

# ===== Utility Rules =================================================================================================

# Format the solidity code.
format:; forge fmt
format-check:; forge fmt --check

# Update forge dependencies.
update:; forge update
