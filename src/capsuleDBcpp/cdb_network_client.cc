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

CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize, int id, asylo::CleansingVector<uint8_t> serialized_input_key) {
    LOG(INFO) << "Creating CapsuleDB Network Client";
    CapsuleDB* instance = spawnDB(blocksize);
    this->db = instance;
    this->id = id;

    this->signing_key = asylo::EcdsaP256Sha256SigningKey::CreateFromDer(serialized_input_key).ValueOrDie();
    this->verifying_key = this->signing_key->GetVerifyingKey().ValueOrDie();

    LOG(INFO) << "CapsuleDB Network Client setup complete";
}

void CapsuleDBNetworkClient::put(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    LOG(INFO) << "Got into capsuleDB put function" << std::endl;
    capsule_pdu translated;
    asylo::CapsuleFromProto(&translated, &inPDU);
    
    // Verify hash and signature
    if(!asylo::verify_dc(&translated, verifying_key)){
        std::cout << "Verification failed, not writing to CapsuleDB\n";
        return;
    }

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads
        for (kvs_payload payload : translated.payload_l) {
            db->put(&payload);
        }
    }
    else
        LOG(INFO) <<"Unable to decrypt payload\n";

    return;
}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {
    hello_world::CapsulePDU protoDC;
    
    // Get requested payload from CapsuleDB
    // kvs_payload requested = db->get(requestedKey);
    LOG(INFO) << "Got into GET";
    kvs_payload requested;
    asylo::KvToPayload(&requested, "anotherTestKey", "anotherTestVal", 0, "");
    if (requested.key == "") {
        LOG(INFO) << "Key not present in CapsuleDB";
    }
    
    LOGI << "original msgtype: " << requested.txn_msgType;
    // Generate Vector of kvs_payloads (will only be one in this case)
    std::vector<kvs_payload> outgoingVec;
    outgoingVec.push_back(requested);
    
    // Create CapsulePDU
    capsule_pdu* dc = new capsule_pdu();
    asylo::PayloadListToCapsule(dc, &outgoingVec, id);

    // Encrypt
    bool success = asylo::encrypt_payload_l(dc, true);
    if (!success) {
        LOG(INFO) << "Payload_l encryption failed\n";
        delete dc;
        return protoDC;
    }

    // Hash
    success = asylo::generate_hash(dc);
    if (!success) {
        LOG(INFO) << "Hash generation failed\n";
        delete dc;
        return protoDC;
    }
    LOGI << "SIGNATURE: " << dc->signature;

    // Sign (same issue as cdb_test signing)
    success = asylo::sign_dc(dc, signing_key);
    if (!success) {
        std::cout << "DC signing failed!\n";
        delete dc;
        return protoDC;
    }

    DUMP_CAPSULE(dc);

    // Convert to proto and return
    asylo::CapsuleToProto(dc, &protoDC);
    delete dc;
    return protoDC;
}

/*
 * One example of a handler that may or may not be what we want. 
 */
hello_world::CapsulePDU CapsuleDBNetworkClient::handle(const hello_world::CapsulePDU inPDU) {
    // Convert proto to pdu
    LOGI << "Got into capsuleDB handle function";
    capsule_pdu translated;
    asylo::CapsuleFromProto(&translated, &inPDU);
    hello_world::CapsulePDU empty;
    
    // Verify hash and signature
    if(!asylo::verify_dc(&translated, verifying_key)){
        LOG(INFO) << "Verification failed, not writing to CapsuleDB";
        return empty;
    }

    // Decrypt pdu paylaod
    if(asylo::decrypt_payload_l(&translated)) {
    // Convert decrypted payload into vector of kvs_payloads

        // TODO: fix batch request logic, this will not work properly
        // LOG(INFO) << "ret addr: " << translated.retAddr;
        for (kvs_payload payload : translated.payload_l) {
            if (payload.txn_msgType == "") {
                db->put(&payload);
            } else if (payload.txn_msgType == CDB_GET) {
                return get(payload.key);
            }
        }
    }
    else
        LOG(INFO) <<"Unable to decrypt payload\n";

    return empty;
}