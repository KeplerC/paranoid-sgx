#ifndef ENGINE_H
#define ENGINE_H

/*
 * This file manages the database as well as read/write requests.  
 */

#include <string>
#include <vector>
#include <map>
#include "memtable_new.hpp"
//#include "../benchmark.h"
#include "absl/strings/string_view.h"
#include "index.hh"

// using namespace asylo;

class CapsuleDB {
    public:
        std::map <std::string, std::string> test_map;
        std::string name;
        int maxLevels = 5;
        std::string targetCapsule;
        int test_count=0;
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
            test_map.insert({key, value});
            kvs_payload kvs;
            kvs.key = key;
            kvs.value = value;

            kvs.txn_timestamp = std::chrono::system_clock::to_time_t(
                           std::chrono::system_clock::now());
            put(&kvs);
        }
        void benchmark_get(std::string key)
        {
            get(key);
        }

        void benchmark_verify() {
            int num_found = 0;
            std::vector<std::string> failed_keys; 
            for(const auto& [key, value] : test_map) {
                std::string value1 = get(key);
                if(value1==""){
                    failed_keys.push_back(key);
                    std::cout << key << "not found in capsuleDB";
                    test_count++;
                }
                if(value1 == value){
                    num_found++;
                }
            }
            std::cout << "no.of.keys not found is:"<<test_count << "\n";
            std::cout << "no.of.keys found is:"<<num_found <<"\n";
            std::cout << "size of test_map" <<test_map.size() <<"\n"; 
            for(int x=0; x <failed_keys.size();x++)
                std::cout << failed_keys.at(x)<<" ";
        }

        void benchmark2(){
            for(int i=1; i<2000; i++)
            {
                test_map.insert({std::to_string(i),std::to_string(i)});
                kvs_payload kvs;
                kvs.key = std::to_string(i);
                kvs.value = std::to_string(i);

                kvs.txn_timestamp = std::chrono::system_clock::to_time_t(
                               std::chrono::system_clock::now());
                put(&kvs);
            }
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
