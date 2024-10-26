# Makefile

# Load environment variables from .env
include .env
export $(shell sed 's/=.*//' .env) # Export all variables from .env


# deploy to sepolia
deploy_sepolia:
	@echo "Deploying to Sepolia"
	@echo "SEPOLIA_RPC_URL = $(SEPOLIA_RPC_URL)"
	@echo "MINTER_ADDRESS = $(SEPOLIA_MINTER_ADDRESS)"
	forge script --chain sepolia script/Deposit.s.sol:DeployDeposit --rpc-url $(SEPOLIA_RPC_URL) --broadcast --verify -vvvv

# deploy to bnb testnet
deploy_bnb_testnet:
	@echo "Deploying to BNB testnet"
	@echo "BSCTEST_RPC_URL = $(BSCTEST_RPC_URL)"
	@echo "MINTER_ADDRESS = $(BSCTEST_MINTER_ADDRESS)"
	@echo "BNBSCAN_API" = $(BNBSCAN_API)
	forge script --chain sepolia script/Deposit.s.sol:DeployDeposit --rpc-url $(BSCTEST_RPC_URL) --broadcast --verifier-url https://bscscan.com/ --etherscan-api-key  $(BNBSCAN_API)  --verify -vvvv
