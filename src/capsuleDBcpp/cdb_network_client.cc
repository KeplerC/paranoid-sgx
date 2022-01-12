#include "cdb_network_client.hh"

#include <vector>
#include <iostream>
#include <memory>

#include "../util/proto_util.hpp"
#include "../kvs_include/capsule.h"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize, int id, std::string priv_key, 
    std::string pub_key, std::unique_ptr <asylo::SigningKey> signing_key, std::unique_ptr <asylo::VerifyingKey> verifying_key) {
    db = spawnDB(blocksize);
    this->id = id;
    this->priv_key = priv_key;
    this->pub_key = pub_key;
    this->signing_key = signing_key;
    this->verifying_key = verifying_key;
}

void CapsuleDBNetworkClient::put(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    capsule_pdu translated;
    asylo::CapsuleFromProto(&translated, &inPDU);
    
    // Verify hashe and signature
    if(!asylo::verify_dc(&translated, verifying_key)){
        std::cout << "Verification failed, not writing to CapsuleDB\n";
        return;
    }

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads
        for (kvs_payload payload : translated.payload_l) {
            db.put(&payload);
        }
    }
    else
        std::cout <<"Unable to decrypt payload\n";
    return;
}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {
    hello_world::CapsulePDU protoDC;
    
    // Get requested payload from CapsuleDB
    kvs_payload requested = db.get(requestedKey);
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
