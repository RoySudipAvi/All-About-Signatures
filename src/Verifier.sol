// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

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

contract Verifier {
    struct Message {
        string _message;
    }

    struct Person {
        address _wallet;
        string _name;
    }

    struct Content {
        string _subject;
        string _text;
    }

    struct Mail {
        Person _from;
        Person _to;
        string _subject;
        string _text;
    }

    /// @notice keccak256 hashing of the type itself
    bytes32 public constant DOMAIN_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 public constant MESSAGE_TYPE_HASH =
        keccak256("Message(string _message)");

    bytes32 public constant PERSON_TYPE_HASH =
        keccak256("Person(address _wallet,string _name)");

    bytes32 public constant CONTENT_TYPE_HASH =
        keccak256("Content(string _subject,string _text)");

    bytes32 public constant MAIL_TYPE_HASH =
        keccak256(
            "Mail(Person _from,Person _to,string _subject,string _text)Person(address _wallet,string _name)"
        );

    bytes32 public immutable I_DOMAIN_SEPERATOR;

    constructor(string memory _name, string memory _version) {
        I_DOMAIN_SEPERATOR = _hashDomain(
            _name,
            _version,
            block.chainid,
            address(this)
        );
    }

    function testMessage(
        string memory _message
    ) external pure returns (bytes memory) {
        return bytes(_message);
    }

    function getVRSFromSignature(
        bytes memory _signature
    ) public pure returns (uint8, bytes32, bytes32) {
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

    /// @notice Converting uint256 to string. Alternatively we can use openzeppeling Strings library. Example given below
    function _uintToString(
        uint256 _number
    ) private pure returns (string memory) {
        uint _digits = 1;
        uint _num = _number;
        while ((_num /= 10) != 0) {
            _digits++;
        }
        bytes memory _result = new bytes(_digits);
        while (_digits != 0) {
            _digits--;

            // The ASCII value of the modulo 10 value
            _result[_digits] = bytes1(uint8(0x30 + (_number % 10)));
            _number /= 10;
        }
        return string(_result);
    }

    /// @notice Converting uint256 to string using openzeppelin Strings library.
    function _uintToStringUsingOpenzeppelinStrings(
        uint256 _number
    ) private pure returns (string memory) {
        return Strings.toString(_number);
    }

    function _getDigest(
        bytes memory _prefixData
    ) private pure returns (bytes32) {
        return keccak256(_prefixData);
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////// personal_sign verification //////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////

    /// @notice It maintains the EIP-191 format for signed data
    /// @notice 0x19 <1 byte version> <version specific data> <data to sign>
    /// <1 byte version> is bytes1(0x45) for personal_sign which is equivalent to "E"
    /// <version specific data> is "thereum Signed Message:\n" + _uintToStringUsingOpenzeppelinStrings(bytes(_message).length)
    /// <data to sign> is _message
    function _prefiixMessage(
        string memory _message
    ) private pure returns (bytes memory) {
        bytes memory _prefix = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x45),
            "thereum Signed Message:\n",
            _uintToStringUsingOpenzeppelinStrings(bytes(_message).length),
            _message
        );

        return _prefix;
    }

    function getSigner(
        string memory _message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external pure returns (address) {
        bytes memory _prefix = _prefiixMessage(_message);
        bytes32 _digest = _getDigest(_prefix);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////// EIP-712 standard ////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////

    /// @notice using keccak256 on _name and _version to keep it 32 bytes
    /// @notice the format of data inside abi.encode for this particular type of(EIP-712 hashing of struct data) case
    /// is Hash of the struct type, followed by all the data.
    function _hashDomain(
        string memory _name,
        string memory _version,
        uint256 _chainid,
        address _verifyingAddress
    ) private pure returns (bytes32) {
        bytes32 _hash = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH,
                keccak256(bytes(_name)),
                keccak256(bytes(_version)),
                _chainid,
                _verifyingAddress
            )
        );
        return _hash;
    }

    /////////////////////// For Single Struct ////////////////////////////////////////////////

    /// @notice format of the data remains same irrespective of how many structs are there
    /// a) the definition of struct b) the 32 bytes hash of the struct type (HASH_TYPE) and
    /// c) and 32 bytes hash of the HASH_TYPE and it's values

    function _prefixMessageEIP712(
        Message memory _message
    ) private view returns (bytes memory) {
        bytes memory _prefix = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            I_DOMAIN_SEPERATOR,
            _hashMessage(_message)
        );

        return _prefix;
    }

    /// @notice using keccak256 on _message._message to keep it 32 bytes
    /// @notice the format of data inside abi.encode for this particular type of(EIP-712 hashing of struct data) case
    /// is Hash of the struct type, followed by all the data.
    function _hashMessage(
        Message memory _message
    ) private pure returns (bytes32) {
        bytes32 _hash = keccak256(
            abi.encode(MESSAGE_TYPE_HASH, keccak256(bytes(_message._message)))
        );
        return _hash;
    }

    function getSignerEIP712(
        Message memory _message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external view returns (address) {
        bytes memory _prefix = _prefixMessageEIP712(_message);
        bytes32 _digest = keccak256(_prefix);
        ///(uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }

    /////////////////////// For 2 Structs ////////////////////////////////////////////////

    function _hashPerson(Person memory _person) private pure returns (bytes32) {
        bytes32 _hash = keccak256(
            abi.encode(
                PERSON_TYPE_HASH,
                _person._wallet,
                keccak256(bytes(_person._name))
            )
        );
        return _hash;
    }

    function _hashContent(
        Content memory _content
    ) private pure returns (bytes32) {
        bytes32 _hash = keccak256(
            abi.encode(
                CONTENT_TYPE_HASH,
                keccak256(bytes(_content._subject)),
                keccak256(bytes(_content._text))
            )
        );
        return _hash;
    }

    function _hashMail(Mail memory _mail) private pure returns (bytes32) {
        bytes32 _hash = keccak256(
            abi.encode(
                MAIL_TYPE_HASH,
                _hashPerson(_mail._from),
                _hashPerson(_mail._to),
                keccak256(bytes(_mail._subject)),
                keccak256(bytes(_mail._text))
            )
        );
        return _hash;
    }

    function _prefixMail(
        Mail memory _mail
    ) private view returns (bytes memory) {
        bytes memory _prefix = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            I_DOMAIN_SEPERATOR,
            _hashMail(_mail)
        );
        return _prefix;
    }

    function getSignerMail(
        Mail memory _mail,
        bytes memory _signature
    ) external view returns (address) {
        bytes32 _digest = keccak256(_prefixMail(_mail));
        (uint8 _v, bytes32 _r, bytes32 _s) = getVRSFromSignature(_signature);
        address _signer = ecrecover(_digest, _v, _r, _s);
        return _signer;
    }
}
