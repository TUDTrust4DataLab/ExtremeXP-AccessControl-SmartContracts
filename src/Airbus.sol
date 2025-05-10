// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;


import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IPDP.sol";
import "./interfaces/IUseCaseRule.sol";

contract Airbus is AccessControl, IUseCaseRule {
    

    struct User {
        string name;
        string location;
        string ipAddress;
        bool isDataProcessor;
        bool isAnonymized;
    }

    struct File {
        bytes32 fileHash;
        bool isAnonymized;
    }

    struct Resource {
        bytes32 resourceId;
        uint8 operationType; // 1: read, 2: write
    }

    struct Contract {
        bytes32 contractHash;
        bytes32 signedHash;
    }
    
    
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
        function isDPAHashValid(bytes32 providedHash, bytes32 storedHash) public pure returns (bool) {
        if(providedHash != storedHash) {
            return false; 
        }
        else {
            return true;
        }
    }
    // END OF CONTEXT ATTRIBUTES

   function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
        // Waiting: (string day, uint8 hour, string ip, bytes32[] allowedIPs, int256 userLat, int256 userLon, Location[] allowedLocations, bytes32 providedDPAHash, bytes32 storedDPAHash)
        (
            string memory day,
            uint8 hour,
            string memory ip,
            bytes32[] memory allowedIPs,
            int256 userLat,
            int256 userLon,
            Location[] memory allowedLocations,
            bytes32 providedDPAHash,
            bytes32 storedDPAHash
        ) = abi.decode(parameters[0], (string, uint8, string, bytes32[], int256, int256, Location[], bytes32, bytes32));

        bool granted = false;

        bool isWeekday = keccak256(bytes(day)) != keccak256(bytes("6")) && keccak256(bytes(day)) != keccak256(bytes("7"));
        bool isWorkHour = hour >= 9 && hour <= 17;
        bool ipOk = isIPWhitelisted(ip, allowedIPs);
        bool locationOk = isUserNearApprovedLocation(userLat, userLon, allowedLocations, 1000);
        bool dpaOk = isDPAHashValid(providedDPAHash, storedDPAHash);

        if (
            isWeekday &&
            isWorkHour &&
            ipOk &&
            locationOk &&
            dpaOk
        ) {
            granted = true;
        }

        IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);
    }


}