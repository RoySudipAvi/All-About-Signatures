// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {Verifier, InvalidSignature, InvalidSignatureLength} from "src/Verifier.sol";
import {Vm} from "forge-std/Vm.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {HelperConfig, VeriferDeploy} from "script/Verifier.s.sol";

contract VerifierTest is Test {
    using MessageHashUtils for bytes32;

    uint256 private constant PRIVATE_KEY =
        0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e;
    Verifier private s_signatures;
    address private s_signer;
    Vm.Wallet private s_aliceWallet;

    uint256 private constant HIGH_S =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0 + 1;

    function setUp() external {
        VeriferDeploy deploy = new VeriferDeploy();
        s_signatures = deploy.run();
        //s_signatures = new Verifier("Demo Signatures", "1.0");
        s_signer = vm.addr(PRIVATE_KEY);
        s_aliceWallet = vm.createWallet("alice");
    }

    // function testDumps() external view {
    //     console.log(s_signer); // Signer address
    //     console.log(s_aliceWallet.addr); // Another Signer Address
    //     console.logString(s_signatures.uintToString(45)); // uint to string test
    //     console.logBytes(s_signatures.prefixData(bytes1(0x00), "Lorem Ipsum DOler SIt AMut")); // prefix test for data for validator
    //     console.logBytes(s_signatures.prefixData(bytes1(0x45), "Lorem Ipsum DOler SIt AMut")); // prefix test gfor personal signing
    // }

    function _makeHighSBytesSig(
        bytes32 digest
    ) internal returns (bytes memory) {
        // create a valid signature first
        (uint8 v, bytes32 r, ) = vm.sign(PRIVATE_KEY, digest);
        // force s to be too large
        bytes32 badS = bytes32(HIGH_S);
        return abi.encodePacked(r, badS, v);
    }

    function testPersonalSignRevertOnHighS() external {
        string memory msg_ = "Personal test";
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(bytes(msg_));
        bytes memory badSig = _makeHighSBytesSig(digest);

        vm.expectRevert(InvalidSignature.selector);
        s_signatures.personalMessageSign(msg_, badSig);
    }

    function testPersonalSignRevertForInvalidSignatureLength() external {
        bytes memory invalidSig = new bytes(64);
        string memory msg_ = "Personal test";
        vm.expectRevert(InvalidSignatureLength.selector);
        s_signatures.personalMessageSign(msg_, invalidSig);
    }

    function testPersonalSignMutatedMessage() external {
        string memory _message = "Ethereum is based";
        bytes memory _messageBytes = bytes(_message);
        bytes32 _digest = MessageHashUtils.toEthSignedMessageHash(
            _messageBytes
        );
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(s_aliceWallet, _digest);
        bytes memory _signature = abi.encodePacked(_r, _s, _v);
        string memory _messageWrong = "Ethereum is baaad";
        address _signerReturnedWrong = s_signatures.personalMessageSign(
            _messageWrong,
            _signature
        );

        address _signerReturned = s_signatures.personalMessageSign(
            _message,
            _signature
        );

        assertNotEq(_signerReturned, _signerReturnedWrong);
    }

    function testSignForValidators() external {
        string memory _message = "Ethereum is based";
        bytes memory _messageBytes = bytes(_message);
        bytes32 _digest = MessageHashUtils.toDataWithIntendedValidatorHash(
            address(s_signatures),
            _messageBytes
        );
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(PRIVATE_KEY, _digest);
        bytes memory _signature = abi.encodePacked(_r, _s, _v);
        console.logBytes(_signature);
        address _signerReturned = s_signatures.getSignerForValidator(
            _message,
            _signature
        );
        console.log(_signerReturned);
        assertEq(s_signer, _signerReturned);
    }

    function testPersonalSign() external {
        string memory _message = "Ethereum is based";
        bytes memory _messageBytes = bytes(_message);
        bytes32 _digest = MessageHashUtils.toEthSignedMessageHash(
            _messageBytes
        );
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(s_aliceWallet, _digest);
        bytes memory _signature = abi.encodePacked(_r, _s, _v);
        address _singerReturned = s_signatures.personalMessageSign(
            _message,
            _signature
        );
        assertEq(s_aliceWallet.addr, _singerReturned);
    }

    function testStructuredDataSign() external {
        string memory _message = "Signing EIP-712 data";
        bytes32 _hashStructMessage = keccak256(
            abi.encode(
                s_signatures.MESSAGE_TYPE_HASH(),
                keccak256(bytes(_message)),
                s_signer
            )
        );
        bytes32 _digest = MessageHashUtils.toTypedDataHash(
            s_signatures.I_DOMAIN_SEPERATOR(),
            _hashStructMessage
        );
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(PRIVATE_KEY, _digest);
        bytes memory _signature = abi.encodePacked(_r, _s, _v);
        console.logBytes(_signature);
        console.log(s_signer);
        Verifier.Message memory _Message = Verifier.Message({
            message: _message,
            sender: s_signer
        });
        address _signerReturned = s_signatures.getSignerStructuredData(
            _Message,
            _signature
        );
        assertEq(s_signer, _signerReturned);
    }

    function testMultipleStructuredDataSign() external {
        Verifier.Branch memory _branchFrom = Verifier.Branch({
            id: 3,
            name: "Audit"
        });

        Verifier.Person memory _personFrom = Verifier.Person({
            name: "Chotu",
            wallet: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8,
            branch: _branchFrom
        });

        Verifier.Branch memory _branchTo = Verifier.Branch({
            id: 2,
            name: "Web3 Development"
        });

        Verifier.Person memory _personTo = Verifier.Person({
            name: "Golu",
            wallet: 0x976EA74026E726554dB657fA54763abd0C3a0aa9,
            branch: _branchTo
        });

        Verifier.Mail memory _mail = Verifier.Mail({
            from: _personFrom,
            to: _personTo,
            subject: "Issue regarding reentrancy",
            content: "In the withdraw function there is an issue of reentrancy, make sure to follow CEI pattern"
        });

        bytes32 _hashStructMail = s_signatures.hashStructMail(_mail);
        bytes32 _digest = MessageHashUtils.toTypedDataHash(
            s_signatures.I_DOMAIN_SEPERATOR(),
            _hashStructMail
        );
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(s_aliceWallet, _digest);
        bytes memory _signature = abi.encodePacked(_r, _s, _v);
        console.logBytes(_signature);
        address _signerReturned = s_signatures
            .getSignerStructuredDataMultipleStructs(_mail, _signature);
        assertEq(s_aliceWallet.addr, _signerReturned);
    }
}
