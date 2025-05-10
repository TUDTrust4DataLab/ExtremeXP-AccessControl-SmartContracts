// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/IUseCaseRule.sol";
import "./interfaces/IPDP.sol";

contract I2cat is IUseCaseRule {
    using ECDSA for bytes32;

    
    struct Location {
        int256 lat;
        int256 longi;
    }

    constructor() {}

    modifier onlyHTTPS(string memory protocol) {
        require(keccak256(abi.encodePacked(protocol)) == keccak256("HTTPS"), "Connection must be HTTPS");
        _;
    }

    modifier onlyDuringWorkHours(uint hour, uint weekday) {
        require(hour >= 8 && hour <= 17, "Outside of work hours");
        require(weekday >= 1 && weekday <= 5, "Access only on weekdays");
        _;
    }

    function isWithinRadius(int256 userLat,int256 userLong,int256 approvedLat,int256 approvedLong,uint256 radiusMeters) public pure returns (bool) {
        int256 latDiff = userLat - approvedLat;
        int256 lonDiff = userLong - approvedLong;
        uint256 radiusMicroDeg = (radiusMeters * 1e6) / 111000; // transform meters to microdegrees (approximation)
        return uint256(latDiff ** 2 + lonDiff ** 2) <= radiusMicroDeg ** 2;
    }

    function isIPWhitelisted(string memory ip, bytes32[] memory allowedIPHashes) public pure returns (bool) {
        bytes32 ipHash = keccak256(abi.encodePacked(ip));
        for (uint i = 0; i < allowedIPHashes.length; i++) {
            if (allowedIPHashes[i] == ipHash) {
                return true;
            }
        }
        return false;
    }

    function isUserNearApprovedLocation(
        int256 userLat,
        int256 userLon,
        Location[] memory allowedLocations,
        uint256 radiusMeters
    ) public pure returns (bool) {
        for (uint i = 0; i < allowedLocations.length; i++) {
            Location memory loc = allowedLocations[i];
            if (isWithinRadius(userLat, userLon, loc.lat, loc.longi, radiusMeters)) {
                return true;
            }
        }
        return false;
    }

    // CONTEXT ATTRIBUTES -- INTEGRATION WITH PIP
    function isFileLastVersion(string memory fileHashVersion, string memory fileHashStored) public pure returns (bool) {
            return keccak256(bytes(fileHashVersion)) == keccak256(bytes(fileHashStored));
    }

    function isResourceValidated(bytes32 resourceHash,address[] memory validators,bytes[] memory signatures) public view returns (bool) {
            if (signatures.length < 2 || validators.length < 2 || signatures.length != validators.length) {
                return false;
            }
            bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", resourceHash));
            for (uint i = 0; i < validators.length; i++) {
                address recovered = ethSigned.recover(signatures[i]);
                if (recovered != validators[i]) {
                    return false;
                }
                // verify duplicate signatures
                for (uint j = 0; j < i; j++) {
                    if (validators[j] == validators[i]) {
                        return false;
                    }
                }
    }

            return true;
        }
    function isDPAHashValid(bytes32 providedHash, bytes32 storedHash) public pure returns (bool) {
            if(providedHash != storedHash) {
                return false; 
            }
            else {
                return true;
            }
    }
    function isUserDataAnonymised(bool dataAnonymization) public view returns (bool) {
        if(dataAnonymization == true) {
            return true;
        } else {
            return false;
        }
    }
    // 

    // Optional: emit a log for auditing (without storing sensitive data)
    event LogAccessRequest(address indexed user, bool success, uint timestamp);



   function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
        // Waiting: (string day, uint8 hour, string fileHashVersion, string fileHashStored, bytes32 resourceHash, address[] validators, bytes[] signatures, bytes32 providedDPAHash, bytes32 storedDPAHash, bool dataAnonymized)
        (
            string memory day,
            uint8 hour,
            string memory fileHashVersion,
            string memory fileHashStored,
            bytes32 resourceHash,
            address[] memory validators,
            bytes[] memory signatures,
            bytes32 providedDPAHash,
            bytes32 storedDPAHash,
            bool dataAnonymized
        ) = abi.decode(parameters[0], (string, uint8, string, string, bytes32, address[], bytes[], bytes32, bytes32, bool));

        bool granted = false;

        bool isWeekday = keccak256(bytes(day)) != keccak256(bytes("6")) && keccak256(bytes(day)) != keccak256(bytes("7"));
        bool isWorkHour = hour >= 8 && hour <= 17;
        bool lastVersionOk = isFileLastVersion(fileHashVersion, fileHashStored);
        bool validated = isResourceValidated(resourceHash, validators, signatures);
        bool dpaOk = isDPAHashValid(providedDPAHash, storedDPAHash);
        bool anonOk = isUserDataAnonymised(dataAnonymized);

        if (
            isWeekday &&
            isWorkHour &&
            lastVersionOk &&
            validated &&
            dpaOk &&
            anonOk
        ) {
            granted = true;
        }

        IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);
    }


}
