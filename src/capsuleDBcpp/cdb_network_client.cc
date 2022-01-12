#include "cdb_network_client.hh"
#include "../util/proto_util.hpp"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize = 50) {
    db = CapsuleDB(blocksize);
}

void CapsuleDBNetworkClient::put(hello_world::CapsulePDU inPDU) {
    // Verify hashes
     if(!asylo::verify_hash(&inPDU)){
        std::cout << "hash verification failed, not writing to capsuleDB" << endl;
        return;
     }
    // Decrypt pdu paylaod (Need to update header file to include key (can just hardcode it))
    if(asylo::decrypt_payload_l(&inPDU)) {
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
    // Generate Vector of kvs_payloads (will only be one in this case)
    // Create CapsulePDU
    // Add vector
    // Encrypt, generate hashes
    // Return
}
