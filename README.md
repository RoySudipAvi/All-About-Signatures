## Verifier Solidity Smart Contract

A versatile, security-focused smart contract for verifying Ethereum signatures using:
- **EIP-191 (data with intended validator)**
- **EIP-191 (personal_sign)**
- **EIP-712 (structured data, single and nested structs)**

---

## Features

- **Validator Signature Verification (EIP-191, 0x00):**
  - Verifies messages that are only valid for this contract’s address.
  - Protects against replay attacks across contracts or chains.

- **Personal Sign Verification (EIP-191, 0x45):**
  - Verifies standard `personal_sign` signatures (MetaMask, Foundry cast, etc).
  - Used in SIWE, dApp login, and off-chain authentication.

- **EIP-712 Structured Data Verification:**
  - Supports both simple and deeply nested struct signatures (including your custom `Mail` struct).



## Supported Verification Methods

**EIP-191, Data with Intended Validator:**
Function: getSignerForValidator(string memory _message, bytes memory _signature)

Digest: keccak256(0x19, 0x00, contractAddress, message)

Use case: On-chain meta-tx, replay-safe off-chain authorizations for this contract only.

**EIP-191, personal_sign:**
Function: personalMessageSign(string memory _message, bytes memory _signature)

Digest: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)

Use case: SIWE, login with wallet, generic off-chain proof of address.

**EIP-712, Structured Data:**
a. Message struct
Function: getSignerStructuredData(Message memory _message, bytes memory _signature)

Domain: EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)

Types: Message(string message,address sender)

Digest: keccak256(0x19, 0x01, domainSeparator, hashStructMessage(_message))

Use case: On-chain or off-chain proof of typed data, DAO voting, meta-tx, etc.

b. Mail struct (nested)
Function: getSignerStructuredDataMultipleStructs(Mail memory _mail, bytes memory _signature)

Types: Complex struct with nested Person/Branch .

Use case: cross-contract composability, advanced EIP-712 workflows.

## Supported Verification Methods
**Deploy the contract with name and version:**

Example: "Demo Signatures", "1.0"

**Create signatures off-chain:**

For Validator:

Use a script to sign keccak256(0x19, 0x00, contractAddress, message)

For personal_sign:

Use MetaMask or cast sign-message

For EIP-712:

Use Forge script or ethers.js's signTypedData/MetaMask dApp signing.

See frontend UI README for example scripts.

**Call verification functions:**

Pass the original message data and the signature.

Returns the signer address.

## Security

Enforces signature length and low-s requirement (no malleable signatures).

All digest construction matches standard EIPs.

Always domain-separated to prevent replay.

Note: EIP-712 domain includes contract address and salt for cross-chain protection.

Follow the Makifile for easier deployment.
For example, to deploy the Verifier contract first assign values to all the variable mentioned in Makefile,
then run the the following to deploy on base sepolia.

```shell
make deploy CONTRACT=Verifier NETWORK=base_sepolia
```

### Requirements:

Foundry

Solidity 0.8.28

OpenZeppelin Contracts

### License:

MIT