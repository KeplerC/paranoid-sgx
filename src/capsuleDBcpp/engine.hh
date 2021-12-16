#ifndef ENGINE_H
#define ENGINE_H

/*
 * This file manages the database as well as read/write requests.  
 */

#include <string>
#include <vector>
#include "memtable_new.hpp"
//#include "../benchmark.h"
#include "absl/strings/string_view.h"
#include "index.hh"

// using namespace asylo;

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
        Memtable memtable;
        CapsuleIndex index;
        //M_BENCHMARK_HERE
	#include "../benchmark.h"
        CapsuleDB();
        std::string get(const std::string &key, bool isMulticast = false);
        void put(const kvs_payload *payload);
        void benchmark_put(std::string key, std::string value)
        {
            kvs_payload kvs;
            kvs.key = key;
            kvs.value = value;
            kvs.txn_timestamp = std::chrono::system_clock::to_time_t(
                           std::chrono::system_clock::now());
            put(&kvs);
        }
};

/*
 * This function creates a new CapsuleDB instance.  It takes in information about the sizes of levels and other metadata to establish compaction rules.
 * 
 * Inputs: ???
 * Outputs: An error code
 */
CapsuleDB spawnDB(size_t memtable_size);
int connectDB();

#endif
