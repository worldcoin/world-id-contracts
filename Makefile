# By default we want to build.
all: install build

# ===== Basic Development Rules =======================================================================================

# Install forge dependencies (not needed if submodules are already initialized).
install:; forge install && npm install

# Build contracts.
build:; forge build

# Run tests, with debug information and gas reports.
test:; FOUNDRY_PROFILE=debug forge test

# Clean the solidity build directory.
clean:; rm -rf out/

# Get the contract sizes.
sizes:; forge build --sizes 2>&1 > .size-snapshot

# ===== Profiling Rules ===============================================================================================

# Benchmark the tests.
bench:; forge test --gas-report --no-match-test testCannotRegisterIfProofIncorrect

# Snapshot the current test usages.
snapshot:; forge snapshot --no-match-test testCannotRegisterIfProofIncorrect

# ===== Deployment Rules ==============================================================================================

# Deploy contracts
deploy: install build; node --no-warnings scripts/deploy.js deploy

# Upgrade contracts
upgrade: install build; node --no-warnings scripts/deploy.js upgrade

# Deploy contracts
transfer-ownership: install build; node --no-warnings scripts/deploy.js transfer

# ===== Verifier Management Rules =====================================================================================

verifier-add: install build; node --no-warnings scripts/deploy.js verifier-add

verifier-update: install build; node --no-warnings scripts/deploy.js verifier-update

verifier-disable: install build; node --no-warnings scripts/deploy.js verifier-disable

# ===== Router Management Rules =======================================================================================

# Deploys the router contract.
deploy-router: install build; node --no-warnings scripts/deploy.js deploy-router

# Upgrades the router contract.
upgrade-router: install build; node --no-warnings scripts/deploy.js upgrade-router

# Add routes in the router.
route-add: install build; node --no-warnings scripts/deploy.js route-add

# Update routes in the router.
route-update: install build; node --no-warnings scripts/deploy.js route-update

# Disable routes in the router.
route-disable: install build; node --no-warnings scripts/deploy.js route-disable

# ===== Utility Rules =================================================================================================

# Format the solidity code.
format:; forge fmt; npx prettier --write .

# Update forge dependencies.
update:; forge update
