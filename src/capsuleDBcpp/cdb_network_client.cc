/* 
 * This file defines a network interface for CapsuleDB.  It does not include an enclave version of CapsuleDB.
 */


#include "cdb_network_client.hh"

#include <vector>
#include <iostream>
#include <memory>

#include "asylo/platform/primitives/trusted_primitives.h"
#include "absl/strings/string_view.h"

#include "../util/proto_util.hpp"
#include "../kvs_include/capsule.h"
#include "engine.hh"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize, int id, char seed[]) {
    CapsuleDB instance = spawnDB(blocksize);
    this->db = &instance;
    this->id = id;

    this->setKeys(seed);
}

asylo::Status CapsuleDBNetworkClient::setKeys(char seed[]) {
    const absl::string_view signing_key_pem = {
                R"pem(-----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIF0Z0yrz9NNVFQU1754rHRJs+Qt04mr3vEgNok8uyU8QoAoGCCqGSM49
    AwEHoUQDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh2/XyY3ZdNrT8lq7FQ0Z6ENdm
    oG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
    -----END EC PRIVATE KEY-----)pem"
    };

    // signing_key = asylo::EcdsaP256Sha256SigningKey::CreateFromPem(signing_key_pem);
    ASYLO_ASSIGN_OR_RETURN(this->signing_key, asylo::EcdsaP256Sha256SigningKey::CreateFromPem(signing_key_pem));
    ASYLO_ASSIGN_OR_RETURN(this->verifying_key, signing_key->GetVerifyingKey());
}

void CapsuleDBNetworkClient::put(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    std::cout << "Got into capsuleDB put function" << std::endl;
    capsule_pdu translated;
    asylo::CapsuleFromProto(&translated, &inPDU);
    
    // Verify hashe and signature
    /*
    if(!asylo::verify_dc(&translated, verifying_key)){
        std::cout << "Verification failed, not writing to CapsuleDB\n";
        return;
    }
    */

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads
        for (kvs_payload payload : translated.payload_l) {
            db->put(&payload);
        }
    }
    else
        std::cout <<"Unable to decrypt payload\n";
    return;
}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {
    hello_world::CapsulePDU protoDC;
    
    // Get requested payload from CapsuleDB
    kvs_payload requested = db->get(requestedKey);
    if (requested.key == "") {
        std::cout << "Key not present in CapsuleDB\n";
    }
    
    // Generate Vector of kvs_payloads (will only be one in this case)
    std::vector<kvs_payload> outgoingVec;
    outgoingVec.push_back(requested);
    
    // Create CapsulePDU
    capsule_pdu* dc = new capsule_pdu();
    asylo::PayloadListToCapsule(dc, &outgoingVec, id);

    // Encrypt
    bool success = asylo::encrypt_payload_l(dc);
    if (!success) {
        std::cout << "Payload_l encryption failed\n";
        delete dc;
        return protoDC;
    }

    // Hash
    success = asylo::generate_hash(dc);
    if (!success) {
        std::cout << "Hash generation failed\n";
        delete dc;
        return protoDC;
    }

    // Sign
    success = asylo::sign_dc(dc, signing_key);
    if (!success) {
        std::cout << "DC signing failed!\n";
        delete dc;
        return protoDC;
    }

    // Convert to proto and return
    asylo::CapsuleToProto(dc, &protoDC);
    delete dc;
    return protoDC;
}

/*
 * One example of a handler that may or may not be what we want. 
 */
void CapsuleDBNetworkClient::handle(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    std::cout << "Got into capsuleDB handle function" << std::endl;
    capsule_pdu translated;
    asylo::CapsuleFromProto(&translated, &inPDU);
    
    // Verify hash and signature
    /*
    if(!asylo::verify_dc(&translated, verifying_key)){
        std::cout << "Verification failed, not writing to CapsuleDB\n";
        return;
    }
    */

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads
        for (kvs_payload payload : translated.payload_l) {
            if (payload.txn_msgType == "PUT") {
                db->put(&payload);
            } else if (payload.txn_msgType == "GET") {
                // Note: I don't have a backward connection from capsuleDB -> testing coordinator for now, so the return value will be unused.
                get(payload.key);
            }
        }
    }
    else
        std::cout <<"Unable to decrypt payload\n";
    return;
}