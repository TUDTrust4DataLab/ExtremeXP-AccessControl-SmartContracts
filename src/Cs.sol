// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IUseCaseRule.sol";
import "./interfaces/IPDP.sol";

contract CS is AccessControl, IUseCaseRule {
    bytes32 public constant HYDROLOGIST_ROLE = keccak256("HYDROLOGIST_ROLE");
    bytes32 public constant AI_EXPERT_ROLE = keccak256("AI_EXPERT_ROLE");
    //bytes32 public constant END_USER_ROLE = keccak256("END_USER_ROLE");

    uint256 public constant END_USER_RADIUS = 10000; // 10km

    mapping (bytes32 => string) public fileHashStored;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }


    struct Location {
        int256 lat;
        int256 longi;
    }


    modifier onlyHTTPS(string memory protocol) {
        require(keccak256(abi.encodePacked(protocol)) == keccak256("HTTPS"), "Connection must be HTTPS");
        _;
    }

    // WORKING HURS AND WEEKDAYS DOES NOT MAKE SENSE FOR CS, THEY SAID that THEY NEED TO GIVE SUPPORT ON WEEKENDS.

    modifier onlyHydrologist() {
        require(hasRole(HYDROLOGIST_ROLE, msg.sender), "Caller is not a hydrologist");
        _;
    }
    modifier onlyAIExpert() {
        require(hasRole(AI_EXPERT_ROLE, msg.sender), "Caller is not an AI expert");
        _;
    }

    function setupHydrologistRole(address user) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _grantRole(HYDROLOGIST_ROLE, user);
    }

    function setupAIExpertRole(address user, bytes32 role) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _grantRole(AI_EXPERT_ROLE, user);
    }

    function revokeHydrologistRole(address user) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _revokeRole(HYDROLOGIST_ROLE, user);
    }
    function revokeAIExpertRole(address user) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _revokeRole(AI_EXPERT_ROLE, user);
    }

    function setupHashofFile(string memory fileHash) public {
        fileHashStored[keccak256(abi.encodePacked(fileHash))] = fileHash;
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

    // IT IS USEFUL FOR BOTH: PERSONEL THAT NEEDS TO BE 1KM OF THE OFFICE AND THE ENDU USER THAT CAN HAVE ACCESS, BUT HAVE TO BE WITHIN THE COUNTRY. 
    // THE RADIUS PARAMETER CAN BE 1000 TO PERSONAL AND 10000 TO END USER (1KM AND 10KM) AS ERROR MARGIN
    // IF IT BECOME COMPLEX WE CAN LEAVE IT TO REFINE IN THE FUTURE.
    function isUserNearApprovedLocation(int256 userLat,int256 userLon,Location[] memory allowedLocations,uint256 radiusMeters ) public pure returns (bool) {
        for (uint i = 0; i < allowedLocations.length; i++) {
            Location memory loc = allowedLocations[i];
            if (isWithinRadius(userLat, userLon, loc.lat, loc.longi, radiusMeters)) {
                return true;
            }
        }
        return false;
    }

    function isFeedbackUserAIExpert(address userAddress) public view returns (bool) {
        require(hasRole(AI_EXPERT_ROLE, userAddress), "Caller is not an AI expert");
        return true;
        
    }

    function isFeedbackUserHydrologist(address userAddress) public view returns (bool) {
        require(hasRole(HYDROLOGIST_ROLE, userAddress), "Caller is not an hydrologist");
        return true;
       
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

    //END USER HAVE TO BE IN A DISTANCE OF 10KM FROM THE APPROVED LOCATION. THIS CAN REFINED IN THE FUTURE
    function isEndUserwithincountry(int256 userLat,int256 userLon,Location[] memory allowedLocations) public pure returns (bool) {
        for (uint i = 0; i < allowedLocations.length; i++) {
            Location memory loc = allowedLocations[i];
            if (isWithinRadius(userLat, userLon, loc.lat, loc.longi, END_USER_RADIUS)) {
                return true;
            }
        }
        return false;
    }

    // check the integrity of the file
    // the hash of the file is stored in the blockchain, and the hash of the file is sent to the smart contract
    // check the integrity of the file
    function integrityofHash(string memory fileHashVersion) public  returns (bool) {
        if(keccak256(bytes(fileHashVersion)) == keccak256(bytes(fileHashStored[keccak256(abi.encodePacked(fileHashVersion))]))){
            return true;
        }
        else {
            return false;
        }
    }

    // END CONTEXT ATTRIBUTES -- INTEGRATION WITH PIP


    /*function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
        bool granted = false;

        if (hasRole(HYDROLOGIST_ROLE, user) || hasRole(AI_EXPERT_ROLE, user)) {
            granted = true;
        }

        IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);

    }*/


  function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
    (
        int256 userLat,
        int256 userLon,
        bytes32[] memory allowedIPHashes,
        string memory ip,
        string memory fileHashVersion,
        bytes32 storedDPAHash,
        bytes32 providedDPAHash,
        Location[] memory allowedLocations
    ) = abi.decode(parameters[0], (int256, int256, bytes32[], string, string, bytes32, bytes32, Location[]));

    bool granted = false;

    bool hasValidRole = hasRole(HYDROLOGIST_ROLE, user) || hasRole(AI_EXPERT_ROLE, user);
    bool isNear = isUserNearApprovedLocation(userLat, userLon, allowedLocations, 1000);
    bool ipOk = isIPWhitelisted(ip, allowedIPHashes);
    bool hashOk = integrityofHash(fileHashVersion);
    bool dpaOk = isDPAHashValid(providedDPAHash, storedDPAHash);

    if (
        hasValidRole &&
        isNear &&
        ipOk &&
        hashOk &&
        dpaOk
    ) {
        granted = true;
    }

    IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);
}










}