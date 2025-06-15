.PHONY: all test clean deploy fund help install snapshot format anvil 
NETWORK ?= anvil
NETWORK_ARGS := --rpc-url http://127.0.0.1:8545 --account $(LOCAL_ACCOUNT) --broadcast -vvvv
ifeq ($(NETWORK),anvil)
	NETWORK_ARGS := --rpc-url http://127.0.0.1:8545 --account $(LOCAL_ACCOUNT) --broadcast -vvvv
else ifeq ($(NETWORK),base_sepolia)
	NETWORK_ARGS := --rpc-url $(SEPOLIA_RPC_URL) --account $(SEPOLIA_KEY) --broadcast --verify --verifier etherscan --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv
else ifeq ($(NETWORK),mainnet)
	NETWORK_ARGS := --rpc-url $(BASE_RPC_URL) --account $(BASE_KEY) --broadcast --verify --verifier etherscan --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv
else
  $(error Unknown NETWORK '$(NETWORK)'; choose anvil, sepolia or mainnet)
endif

CONTRACT   ?= Verifier
SCRIPT     := script/$(CONTRACT).s.sol
EXTRA_ARGS ?=

deploy:
	forge script $(SCRIPT) $(EXTRA_ARGS) $(NETWORK_ARGS)