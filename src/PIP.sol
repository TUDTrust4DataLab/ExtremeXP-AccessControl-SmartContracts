// SPDX-LICENSE-Identifier: MIT
pragma solidity ^0.8.20;


import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract PIP is AccessControl {

    using ECDSA for bytes32;
    // Define the roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant USER_ROLE = keccak256("KEYCLOACK_ROLE");

    

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // I2CAT, MOBY
   function isFileLastVersion(string memory fileHashVersion, string memory fileHashStored) public pure returns (bool) {
    return keccak256(bytes(fileHashVersion)) == keccak256(bytes(fileHashStored));
}

   

    // I2CAT 
    //(CHECK IF RESOURCE WAS SIGNED BY AT LEAST 2 VALIDATORS. PARTIES). THEY VERIFY IF A RESOURCE WAS PREVIOUSLY VERIFIER BY SECURITY TEAM
    // Here it check if the resource has 2 signatures, but check if the signeres are not the same and if the signature is in fact from the signer - to avoid fraud.
    // But i know it if be complex, you can do it more simple or thing is complex to keyloak, we leave it for the future when implement translator.
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

        // Verifica duplicatas
        for (uint j = 0; j < i; j++) {
            if (validators[j] == validators[i]) {
                return false;
            }
        }
    }

    return true;
}


    // I2CAT, CS, MOBY, Airbus
    function isDPAHashValid(bytes32 providedHash, bytes32 storedHash) public pure returns (bool) {
        if(providedHash != storedHash) {
            return false; 
        }
        else {
            return true;
        }
    }

    //I2CAT. 
    //How they work with training modele for security. There are some end user data, but they need to be anonymised. I do not know how to catch this.
    function isUserDataAnonymised(bool dataAnonymization) public view returns (bool) {
        if(dataAnonymization == true) {
            return true;
        } else {
            return false;
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

    // IDEKO
    function workflowAllowedToExecution(string memory workflow_hash, string memory workflow_hash_stored) public pure returns (bool) {
        return keccak256(abi.encodePacked(workflow_hash)) == keccak256(abi.encodePacked(workflow_hash_stored));
    }

    
    //Moby
    /*function checkHashIntegrity(bytes32 providedHash, bytes32 storedHash) public pure returns (bool) {
        return providedHash == storedHash;
    }*/


}