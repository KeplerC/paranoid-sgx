#ifndef CDB_NETWORK_CLIENT_H
#define CDB_NETWORK_CLIENT_H

#include "src/proto/capsule.pb.h"
#include "engine.hh"

// Not sure if we need an object here to actually hold a db instance?

class CapsuleDBNetworkClient {
    private:
        CapsuleDB db;

    public:
        CapsuleDBNetworkClient(size_t blocksize = 50);
        void put(hello_world::CapsulePDU inPDU);
        hello_world::CapsulePDU get(std::string requestedKey);
};

#endif