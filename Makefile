all: install build
# Install forge dependencies (not needed if submodules are already initialized).
install:; forge install && npm install
# Build contracts and inject the Poseidon library.
build:; forge build && node ./src/test/scripts/generate-circom-lib.js
# Run tests, with debug information and gas reports.
test:; FOUNDRY_PROFILE=debug forge test --gas-report
# Format the solidity code.
format:; forge fmt
# Update forge dependencies.
update:; forge update
# Deploy contracts
deploy:; node --no-warnings scripts/deploy.js
