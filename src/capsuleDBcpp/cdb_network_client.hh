#ifndef CDB_NETWORK_CLIENT_H
#define CDB_NETWORK_CLIENT_H

#include <string>
#include <memory>

#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/aead_cryptor.h"

#include "src/proto/hello.pb.h"
#include "engine.hh"
#include "asylo/client.h"


class CapsuleDBNetworkClient {
    private:
        CapsuleDB* db;
        int id;
        std::string priv_key;
        std::string pub_key;
        std::unique_ptr <asylo::SigningKey> signing_key;
        std::unique_ptr <asylo::VerifyingKey> verifying_key;

        asylo::Status setKeys(char seed[]);

    public:
        CapsuleDBNetworkClient(size_t blocksize, int id, char seed[]); 
        void put(hello_world::CapsulePDU inPDU);
        void handle(hello_world::CapsulePDU inPDU);
        hello_world::CapsulePDU get(std::string requestedKey);
};

#endif