// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IUseCaseRule.sol";
import "./interfaces/IPDP.sol";


contract Ideko is AccessControl, IUseCaseRule {

    // CHANGE TO IDEKO ROLES
    bytes32 public constant IDEKO_ROLE = keccak256("IDEKO_TEAM_ROLE");


    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    mapping(bytes32 => mapping(bytes32 => bool)) public workflowDatasetAccess;

    struct Location {
        int256 lat;
        int256 longi;
    }

    function setupIDEKORole(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(IDEKO_ROLE, user);
    }

    function revokeIDEKORole(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(IDEKO_ROLE, user);
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

    // CHANGE TO IDEKO ROLES
    modifier onlyIDEKO() {
        require(hasRole(IDEKO_ROLE, msg.sender), "Caller does not belongs to IDEKO");
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


    function removeDatasetForWorkflow(string memory workflowHash, string memory datasetHash) public {
        bytes32 workflowKey = keccak256(abi.encodePacked(workflowHash));
        bytes32 datasetKey = keccak256(abi.encodePacked(datasetHash));
        delete workflowDatasetAccess[workflowKey][datasetKey];
    }

    //  CONTEXT ATTRIBUTES -- INTEGRATION WITH PIP
    function workflowAllowedToExecution(string memory workflow_hash, string memory workflow_hash_stored) public pure returns (bool) {
        return keccak256(abi.encodePacked(workflow_hash)) == keccak256(abi.encodePacked(workflow_hash_stored));
    }

    // They said that need to force to use specifics datasets in a workflow.
    function allowDatasetForWorkflow(string memory workflowHash, string memory datasetHash) public {
        bytes32 workflowKey = keccak256(abi.encodePacked(workflowHash));
        bytes32 datasetKey = keccak256(abi.encodePacked(datasetHash));
        workflowDatasetAccess[workflowKey][datasetKey] = true;
    }
    // In the last function we register the dataset to workflow, here is the function to check if the dataset is allowed for the workflow. Here is the rule
    function isDatasetAllowedForWorkflow(string memory workflowHash, string memory datasetHash) public view returns (bool) {
        bytes32 workflowKey = keccak256(abi.encodePacked(workflowHash));
        bytes32 datasetKey = keccak256(abi.encodePacked(datasetHash));
        return workflowDatasetAccess[workflowKey][datasetKey];
    }


    // END CONTEXT ATTRIBUTES -- INTEGRATION WITH PIP

    

    function evaluateAccessAndCallPDP(address user,string memory resourceID,bytes[] memory parameters,address pdpAddress) external override {
        // Waiting: (string workflowHash, string workflowHashStored, string datasetHash, string ip, bytes32[] allowedIPs, int256 userLat, int256 userLon, Location[] allowedLocations)

        (
            string memory workflowHash,
            string memory workflowHashStored,
            string memory datasetHash,
            string memory ip,
            bytes32[] memory allowedIPs,
            int256 userLat,
            int256 userLon,
            Location[] memory allowedLocations
        ) = abi.decode(parameters[0], (string, string, string, string, bytes32[], int256, int256, Location[]));

        bool granted = false;

        bool hasRoleAccess = hasRole(IDEKO_ROLE, user);
        bool workflowOk = workflowAllowedToExecution(workflowHash, workflowHashStored);
        bool datasetOk = isDatasetAllowedForWorkflow(workflowHash, datasetHash);
        bool ipOk = isIPWhitelisted(ip, allowedIPs);
        bool locationOk = isUserNearApprovedLocation(userLat, userLon, allowedLocations, 1000);

        if (
            hasRoleAccess &&
            workflowOk &&
            datasetOk &&
            ipOk &&
            locationOk
        ) {
            granted = true;
        }

        IPDP(pdpAddress).receiveAccessDecision(user, resourceID, granted);
    }





}
