// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {console} from "forge-std/console.sol";

error InvalidSignatureLength();
error InvalidSignature();

/// Contract is implementing EIP-191 standard for message signing. It also uses EIP-712 for structured data for message signing
/// Irrespective of the version type, that is
/// a) Data with intended validator(0x00), b) Structured data(0x01), c) personal_sign messages(0x45)
/// format remains the same - 0x19 <1 byte version> <version specific data> <data to sign>
/// <1 byte version> - a)0x00 b) 0x01 c) 0x45 (either of the three)
/// <version specific data> - a) for 0x00 - Data with intended validator, it can be address(this) if this contract is the validator
/// b) for 0x01 - Structured data(EIP-712) - Domain Seperator, in our contract denoted by I_DOMAIN_SEPERATOR
/// c) for 0x45 - personal_sign messages - "thereum Signed Message:\n"+ string representation of length of message.
/// ecrecover function takes keccak256 hash of encoded message and v,r,s
/// the format of encoded message is abi.encodePacked(bytes1(0x19),bytes1(version),version specific data,data to sign);

/// @title Implementation of signatures
/// @author Sudip Roy
/// @notice A very basic implementation to get a clear understanding(hopefully) of EIP-191,EIP-712
/// @custom:experimental This is an experimental contract.
contract Verifier {
    struct Message {
        string message;
        address sender;
    }

    struct Branch {
        uint256 id;
        string name;
    }

    struct Person {
        string name;
        address wallet;
        Branch branch;
    }

    struct Mail {
        Person from;
        Person to;
        string subject;
        string content;
    }

    /// @notice keccak256 hashing of the types
    bytes32 public constant DOMAIN_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        );
    bytes32 public constant MESSAGE_TYPE_HASH =
        keccak256("Message(string message,address sender)");
    bytes32 public constant BRANCH_TYPE_HASH =
        keccak256("Branch(uint256 id,string name)");
    bytes32 public constant PERSON_TYPE_HASH =
        keccak256(
            "Person(string name,address wallet,Branch branch)Branch(uint256 id,string name)"
        );
    bytes32 public constant MAIL_TYPE_HASH =
        keccak256(
            "Mail(Person from,Person to,string subject,string content)Person(string name,address wallet,Branch branch)Branch(uint256 id,string name)"
        );

    bytes32 public immutable I_DOMAIN_SEPERATOR;
    bytes32 private immutable I_SALT;

    constructor(string memory _name, string memory _version) {
        I_SALT = keccak256(
            abi.encodePacked(address(this).code, block.timestamp)
        );
        I_DOMAIN_SEPERATOR = hashStructDomain(
            _name,
            _version,
            block.chainid,
            address(this),
            I_SALT
        );
    }

    function checkSValue(bytes32 _s) private pure returns (bool) {
        if (
            uint256(_s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            revert InvalidSignature();
        }
        return true;
    }

    function checkVValue(uint8 _v) private pure returns (bool) {
        require(_v == 27 || _v == 28, "Invalid signature 'v' value");
        return true;
    }

    /// @notice Helper function to convert uint to string
    /// @param _number uint256 value to be converted
    /// @return String value of the given uint
    function uintToString(
        uint256 _number
    ) private pure returns (string memory) {
        return Strings.toString(_number);
    }

    /// @notice Splits a signature in it's 3 components using inline assembly
    /// @param _signature bytes signature
    /// @return three components v,r,s
    function getVRSFromSignature(
        bytes memory _signature
    ) private pure returns (uint8, bytes32, bytes32) {
        if (_signature.length != 65) {
            revert InvalidSignatureLength();
        }
        uint8 _v;
        bytes32 _r;
        bytes32 _s;
        assembly {
            _r := mload(add(_signature, 32))
            _s := mload(add(_signature, 64))
            _v := byte(0, mload(add(_signature, 96)))
        }
        return (_v, _r, _s);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////// DATA WITH INTENDED VALIDATOR /////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice get signer for data with intended validator using whole signtature
    /// @notice It maintains the EIP-191 format for signed data
    /// @notice 0x19 <1 byte version> <version specific data> <data to sign>
    /// bytes1(0x00) for data with inteded validtors
    /// <version specific data> is address of the validator for 0x00
    /// <data to sign> is _message
    /// @param _message the message to be verified
    /// @param _signature the signature to be verified against
    /// @return signer address
    function getSignerForValidator(
        string memory _message,
        bytes memory _signature
    ) external view returns (address) {
        bytes memory _prefixData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x00),
            address(this),
            _message
        );
        bytes32 _digest = keccak256(_prefixData);
        (uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        checkSValue(_s);
        checkVValue(_v);
        address _signer = ecrecover(_digest, _v, _r, _s);

        return _signer;
    }

    /// @notice get signer for data with intended validator using v,r,s of signature
    /// @notice It maintains the EIP-191 format for signed data
    /// @notice 0x19 <1 byte version> <version specific data> <data to sign>
    /// bytes1(0x00) for data with inteded validtors
    /// <version specific data> is address of the validator for 0x00
    /// <data to sign> is _message
    /// @param _message the message to be verified
    /// @param _v the v component
    /// @param _r the r component
    /// @param _s the s component
    /// @return signer address
    function getSignerForValidatorFromVRS(
        string memory _message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external view returns (address) {
        bytes memory _prefixData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x00),
            address(this),
            _message
        );
        bytes32 _digest = keccak256(_prefixData);
        checkSValue(_s);
        checkVValue(_v);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////// personal_sign verification //////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////

    /// @notice get signer for personal sign messages using whole signtature
    /// @notice It maintains the EIP-191 format for signed data
    /// @notice 0x19 <1 byte version> <version specific data> <data to sign>
    /// <1 byte version> is bytes1(0x45) for personal_sign which is equivalent to "E"
    /// <version specific data> is "thereum Signed Message:\n" + _uintToStringUsingOpenzeppelinStrings(bytes(_message).length) for 0x45
    /// <data to sign> is _message
    /// @param _message the message to be verified
    /// @param _signature the signature to be verified against
    /// @return signer address
    function personalMessageSign(
        string memory _message,
        bytes memory _signature
    ) external pure returns (address) {
        bytes memory _messageInBytes = bytes(_message);
        uint256 _messageLength = _messageInBytes.length;
        bytes memory _prefixData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x45),
            "thereum Signed Message:\n",
            uintToString(_messageLength),
            _message
        );
        bytes32 _digest = keccak256(_prefixData);

        (uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        checkSValue(_s);
        checkVValue(_v);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////// EIP-712 standard ////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Struct hash of domain
    /// @notice it follows the eip-712 structure of hashStruct, that is
    /// hashStruct = keccak256(abi.encode(typeHash,32 bytes values in the order of struct definition))
    /// @return bytes32 keccak256 hashed value of encode(typeHash||all the struct data)
    function hashStructDomain(
        string memory _name,
        string memory _version,
        uint256 _chainId,
        address _verifyingContract,
        bytes32 _salt
    ) private pure returns (bytes32) {
        bytes memory _encodedData = abi.encode(
            DOMAIN_TYPE_HASH,
            keccak256(bytes(_name)),
            keccak256(bytes(_version)),
            _chainId,
            _verifyingContract,
            _salt
        );
        return keccak256(_encodedData);
    }

    /////////////////////// For Single Struct ////////////////////////////////////////////////

    /// @notice Struct hash of Message struct
    /// @notice it follows the eip-712 structure of hashStruct, that is
    /// hashStruct = keccak256(abi.encode(typeHash,32 bytes values in the order of struct definition))
    /// @return bytes32 keccak256 hashed value of encode(typeHash||all the struct data)
    function hashStructMessage(
        Message memory _message
    ) public pure returns (bytes32) {
        bytes memory _encodedData = abi.encode(
            MESSAGE_TYPE_HASH,
            keccak256(bytes(_message.message)),
            _message.sender
        );
        return keccak256(_encodedData);
    }

    /// @notice get signer for Structured data using whole signtature
    /// @notice It maintains the EIP-191 format for signed data
    /// @notice 0x19 <1 byte version> <version specific data> <data to sign>
    /// <1 byte version> is bytes1(0x01) for Structured data EIP-712
    /// <version specific data> is the domain seperator which is I_DOMAIN_SEPERATOR in our case
    /// <data to sign> is 32 bytes hashed value of Struct Message which is defined in function hashStructMessage(Message memory _message)
    /// @param _message the message to be verified
    /// @param _signature the signature to be verified against
    /// @return signer address
    function getSignerStructuredData(
        Message memory _message,
        bytes memory _signature
    ) external view returns (address) {
        bytes memory _prefixData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            I_DOMAIN_SEPERATOR,
            hashStructMessage(_message)
        );
        bytes32 _digest = keccak256(_prefixData);
        (uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        checkSValue(_s);
        checkVValue(_v);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }

    ///////////////////////////////// FOR MULTIPLE STRUCTS //////////////////////////////////////////////////

    function hashStructBranch(
        Branch memory _branch
    ) private pure returns (bytes32) {
        bytes memory _encoded = abi.encode(
            BRANCH_TYPE_HASH,
            _branch.id,
            keccak256(bytes(_branch.name))
        );
        return keccak256(_encoded);
    }

    function hashStructPerson(
        Person memory _person
    ) private pure returns (bytes32) {
        bytes memory _encoded = abi.encode(
            PERSON_TYPE_HASH,
            keccak256(bytes(_person.name)),
            _person.wallet,
            hashStructBranch(_person.branch)
        );
        return keccak256(_encoded);
    }

    function hashStructMail(Mail memory _mail) public pure returns (bytes32) {
        bytes memory _encoded = abi.encode(
            MAIL_TYPE_HASH,
            hashStructPerson(_mail.from),
            hashStructPerson(_mail.to),
            keccak256(bytes(_mail.subject)),
            keccak256(bytes(_mail.content))
        );

        return keccak256(_encoded);
    }

    function getSignerStructuredDataMultipleStructs(
        Mail memory _mail,
        bytes memory _signature
    ) external view returns (address) {
        bytes memory _prefixData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            I_DOMAIN_SEPERATOR,
            hashStructMail(_mail)
        );
        bytes32 _digest = keccak256(_prefixData);
        (uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        checkSValue(_s);
        checkVValue(_v);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }
}
