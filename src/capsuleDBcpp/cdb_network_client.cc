#include "cdb_network_client.hh"


CapsuleDBNetworkClient::CapsuleDBNetworkClient(size_t blocksize = 50) {
    db = CapsuleDB(blocksize);
}

void CapsuleDBNetworkClient::put(hello_world::CapsulePDU inPDU) {

}

hello_world::CapsulePDU CapsuleDBNetworkClient::get(std::string requestedKey) {

}
