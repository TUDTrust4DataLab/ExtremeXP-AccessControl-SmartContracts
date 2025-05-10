//SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IUseCaseRule.sol";

contract PAP is AccessControl {
    
   address public pdp;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    mapping(string => address) public resourceToContract; // resourceID => use case contract
    mapping(string => address) public useCaseDirectory;   // useCaseName => contract address

    constructor(string[] memory useCaseNames, address[] memory useCaseContracts) {
        require(useCaseNames.length == useCaseContracts.length, "Input length mismatch");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        for (uint i = 0; i < useCaseContracts.length; i++) {
            require(useCaseContracts[i] != address(0), "Invalid address");
            useCaseDirectory[useCaseNames[i]] = useCaseContracts[i];
        }
    }

    function setPDP(address pdpAddress) external onlyRole(ADMIN_ROLE) {
        require(pdpAddress != address(0), "Invalid PDP address");
        pdp = pdpAddress;
    }

    function registerResource(
        string memory resourceID,
        string memory useCaseName
    ) public onlyRole(ADMIN_ROLE) {
        address useCaseContract = useCaseDirectory[useCaseName];
        require(useCaseContract != address(0), "Unknown use case name");
        resourceToContract[resourceID] = useCaseContract;
    }

    function getResourceContract(string memory resourceID) public view returns (address) {
        return resourceToContract[resourceID];
    }

    // PDP chama o PAP, que chama o contrato de caso de uso diretamente
    function delegateAccessEvaluation(address user,string memory resourceID,bytes[] memory parameters) public {
        address useCase = resourceToContract[resourceID];
        require(useCase != address(0), "No use case contract for resource");
        require(pdp != address(0), "PDP address not set");
        IUseCaseRule(useCase).evaluateAccessAndCallPDP(user, resourceID, parameters, pdp);
    }
}