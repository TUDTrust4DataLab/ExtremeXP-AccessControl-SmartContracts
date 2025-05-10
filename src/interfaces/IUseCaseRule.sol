// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


interface IUseCaseRule {
    function evaluateAccessAndCallPDP(
        address user,
        string memory resourceID,
        bytes[] memory parameters,
        address pdpAddress
    ) external;
}

