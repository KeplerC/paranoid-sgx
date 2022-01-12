#include "cdb_network_client.hh"

#include <vector>
#include <iostream>
#include <memory>

#include "../util/proto_util.hpp"
#include "../kvs_include/capsule.h"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize = 50, int id, std::string priv_key, 
    std::string pub_key, std::unique_ptr <asylo::SigningKey> signing_key, std::unique_ptr <asylo::VerifyingKey> verifying_key) {
    db = CapsuleDB(blocksize);
    this->id = id;
    this->priv_key = priv_key;
    this->pub_key = pub_key;
    this->signing_key = signing_key;
    this->verifying_key = verifying_key;
}

void CapsuleDBNetworkClient::put(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    capsule_pdu translated;
    asylo::CapsuleFromProto(translated, inPDU);
    
    // Verify hashes
    if(!asylo::verify_hash(&translated)){
        std::cout << "hash verification failed, not writing to capsuleDB" << endl;
        return;
    }

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads
       for (std::vector<kvs_payload>::iterator it = inPDU->payload_l.begin() ; it != inPDU->payload_l.end(); it++) {
            // Repeatedly put payloads to db
             db.put(&it);
       }
    }
    else
        std::cout <<"Unable to decrypt payload" << endl;
    return;
}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {
    // Get requested payload from CapsuleDB
    kvs_payload requested = db.get(requestedKey);
    if (requested.key == "") {
        std::cout << "Key not present in CapsuleDB\n";
    }
    
    // Generate Vector of kvs_payloads (will only be one in this case)
    std::vector<kvs_payload> outgoingVec;
    outgoingVec.push_back(requested);
    
    // Create CapsulePDU
    capsule_pdu dc* = new capsule_pdu();
    asylo::PayloadListToCapsule(dc, &outgoingVec, id);

    // Encrypt
    bool success = asylo::encrypt_payload_l(dc);
    if (!success) {
        std::cout << "Payload_l encryption failed\n";
        delete dc;
        return;
    }

    // Hash
    success = asylo::generate_hash(dc);
    if (!success) {
        std::cout << "Hash generation failed\n";
        delete dc;
        return;
    }

    // Sign
    success = asylo::sign_dc(dc, signing_key);
    if (!success) {
        std::cout << "DC signing failed!\n";
        delete dc;
        return;
    }

    // Convert to proto and return
    hello_world::CapsulePDU protoDC;
    asylo::CapsuleToProto(dc, &protoDC);
    delete dc;
    return protoDC;
}
