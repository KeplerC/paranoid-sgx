#include "cdb_network_client.hh"
#include "../util/proto_util.hpp"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize = 50) {
    db = CapsuleDB(blocksize);
}

void CapsuleDBNetworkClient::put(hello_world::CapsulePDU inPDU) {
    // Verify hashes
    // Decrypt pdu paylaod (Need to update header file to include key (can just hardcode it))
    // Convert decrypted payload into vector of kvs_payloads
    // Repeatedly put payloads to db
}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {
    // Get requested payload from CapsuleDB
    // Generate Vector of kvs_payloads (will only be one in this case)
    // Create CapsulePDU
    // Add vector
    // Encrypt, generate hashes
    // Return
}
