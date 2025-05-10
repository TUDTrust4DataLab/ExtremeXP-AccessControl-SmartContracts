// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPDP {
    function receiveAccessDecision(
        address user,
        string memory resourceID,
        bool granted
    ) external;
}