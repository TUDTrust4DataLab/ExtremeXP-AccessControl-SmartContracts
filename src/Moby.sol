// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./interfaces/IUseCaseRule.sol";
import "./interfaces/IPDP.sol";


contract Moby is AccessControl, IUseCaseRule{
    
    using ECDSA for bytes32;

    //CHANGE TO MOBY ROLES
    bytes32 public constant DATA_PROCESSOR_ROLE = keccak256("DATA_PROCESSOR_ROLE");
    bytes32 public constant AI_EXPERT_ROLE = keccak256("AI_EXPERT_ROLE");

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

    modifier onlyDuringWorkHours(uint hour, uint weekday) {
        require(hour >= 8 && hour <= 17, "Outside of work hours");
        require(weekday >= 1 && weekday <= 5, "Access only on weekdays");
        _;
    }

    modifier onlyDataProcessor() {
        require(hasRole(DATA_PROCESSOR_ROLE, msg.sender), "Caller is not a Data Processor");
        _;
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

    function integrityofHash(string memory fileHashVersion) public  returns (bool) {
        if(keccak256(bytes(fileHashVersion)) == keccak256(bytes(fileHashStored[keccak256(abi.encodePacked(fileHashVersion))]))){
            return true;
        }
        else {
            return false;
        }
    }
    

    function isDPAHashValid(bytes32 providedHash, bytes32 storedHash) public pure returns (bool) {
        if(providedHash != storedHash) {
            return false; 
        }
        else {
            return true;
        }
    }


    // MOBY - They need that to a third party execute workflow or access their data, the third party have to to approved by multi-signature. -- can be 2 or 3 signs
     // Like the isResourceValidated, ideia is similar
    ///  Verifies multi-signature approval for a third party credential
    ///  credentialHash The hash of the credential being approved
    ///  signers List of expected signer addresses
    ///  signatures List of signatures matching the signers
    function isThirdPartyApproved(bytes32 credentialHash,address[] memory signers,bytes[] memory signatures) public pure returns (bool) {
        // Require at least 2 signatures
        if (signers.length < 2 || signatures.length < 2 || signers.length != signatures.length) {
            return false;
        }
       bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", credentialHash));
        for (uint i = 0; i < signers.length; i++) {
            address recovered = ECDSA.recover(ethSigned, signatures[i]);
            if (recovered != signers[i]) {
                return false; // Signature mismatch
            }

            // Check for duplicates
            for (uint j = 0; j < i; j++) {
                if (signers[j] == signers[i]) {
                    return false; // Verify Duplicate signer
                }
            }
        }

        return true;
    }    



    // END CONTEXT ATTIBUTES

   function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
        // Waiting: (bytes32 credentialHash, address[] signers, bytes[] signatures, string memory ip, bytes32[] allowedIPHashes, string memory fileHashVersion, bytes32 storedDPAHash, bytes32 providedDPAHash, int256 userLat, int256 userLon, Location[] allowedLocations)

        (
            bytes32 credentialHash,
            address[] memory signers,
            bytes[] memory signatures,
            string memory ip,
            bytes32[] memory allowedIPHashes,
            string memory fileHashVersion,
            bytes32 storedDPAHash,
            bytes32 providedDPAHash,
            int256 userLat,
            int256 userLon,
            Location[] memory allowedLocations
        ) = abi.decode(parameters[0], (bytes32, address[], bytes[], string, bytes32[], string, bytes32, bytes32, int256, int256, Location[]));

        bool granted = false;

        bool hasRoleAccess = hasRole(DATA_PROCESSOR_ROLE, user) || hasRole(AI_EXPERT_ROLE, user);
        bool ipOk = isIPWhitelisted(ip, allowedIPHashes);
        bool nearOk = isUserNearApprovedLocation(userLat, userLon, allowedLocations, 1000);
        bool hashOk = integrityofHash(fileHashVersion);
        bool dpaOk = isDPAHashValid(providedDPAHash, storedDPAHash);
        bool signedOk = isThirdPartyApproved(credentialHash, signers, signatures);

        if (
            hasRoleAccess &&
            ipOk &&
            nearOk &&
            hashOk &&
            dpaOk &&
            signedOk
        ) {
            granted = true;
        }

        IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);
    }


   


}