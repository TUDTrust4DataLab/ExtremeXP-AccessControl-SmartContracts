// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPAP {
    function delegateAccessEvaluation(
        address user,
        string memory resourceID,
        bytes[] memory parameters
    ) external;
}