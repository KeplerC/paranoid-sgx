#include <string>
#include <vector>
#include "absl/strings/string_view.h"
#include "memtable_new.hpp"
#include "index.hh"

class CapsuleDB {
    public:
        std::string name;
        int maxLevels = 5;
        std::string targetCapsule;
        std::vector<int> maxLevelSizes; //Each level in bytes
        const absl::string_view signing_key_pem = {
            R"pem(-----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIF0Z0yrz9NNVFQU1754rHRJs+Qt04mr3vEgNok8uyU8QoAoGCCqGSM49
            AwEHoUQDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh2/XyY3ZdNrT8lq7FQ0Z6ENdm
            oG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
            -----END EC PRIVATE KEY-----)pem"
        };
        //TODO
        Memtable *memtable;
        std::vector<CapsuleIndex> capIndexVec;
        char* get(const std::string &key, Enclave requester, bool isMulticast = false);
};
