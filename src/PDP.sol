// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/AccessControl.sol";

import "./PAP.sol";
import "./PIP.sol";
import "./interfaces/IUseCaseRule.sol";
import "./interfaces/IPAP.sol";

contract PDP is AccessControl {
    
  bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    address public pap;

    event AccessRequested(address indexed user, string resourceID);
    event AccessResult(address indexed user, string resourceID, bool granted);

    constructor(address papAddress) {
        require(papAddress != address(0), "Invalid PAP address");
        pap = papAddress;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function requestAccess(address user, string memory resourceID, bytes[] memory parameters) public {
        emit AccessRequested(user, resourceID);
        IPAP(pap).delegateAccessEvaluation(user, resourceID, parameters);
    }

    function receiveAccessDecision(address user, string memory resourceID, bool granted) public {
        emit AccessResult(user, resourceID, granted);
    }

}