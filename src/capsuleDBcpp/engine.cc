/*
 * This file manages the database as well as read/write requests.  
 */

#include <iostream>
#include <string>
#include "memtable_new.hpp"
#include "../common.h"
#include "engine.hh"

// using namespace asylo;

CapsuleDB::CapsuleDB() {

}

/*
 * This function creates a new CapsuleDB instance.  It takes in information about the sizes of levels and other metadata to establish compaction rules.
 * 
 * Inputs: ??? (Maybe name?)
 * Outputs: An error code
 */
CapsuleDB spawnDB()
{
    CapsuleDB newInstance = CapsuleDB();
    newInstance.memtable = Memtable();
    newInstance.index = CapsuleIndex();
    return newInstance;
}

/*
 * This function connects to a CapsuleDB instance.
 * 
 * Input: None
 * Output: An error code
 */
int connectDB()
{
    return 0;
}

/*
 * This function takes in a kvs_payload and writes it to CapsuleDB
 *
 * Input: A kvs payload
 * Output: Nothing
 */
void CapsuleDB::put(const kvs_payload *payload)
{
    if (!memtable.put(payload, this->index))
    {
        std::cout << "Failed to write key in the Database";
    }
}

/* 
 * This function retrieves a key from CapsuleDB.  It queries the DataCapsule for the most recent index and then traverses the DataCapsule to find the requested key.
 * It returns the value either directly to the requesting enclave or multicasts it depending on selected mode.
 *
 * Inputs: The key whose value is requested, the requesting enclave, and a return mode.
 * Output: The requested value or an error if the key does not exist.
 */
std::string CapsuleDB::get(const std::string &key, bool isMulticast /* default is already false from function declaration in engine.hh */)
{
    int level_info;
    kvs_payload kv = memtable.get(key);
    std::string block_info, k;
    // unsigned char v[];
    // int t;

    if (kv.key == "") //Checks for key in memtable, if not present: checks in levels
    {
        // TODO iterate if there are multiple capsule indices
        level_info = this->index.getNumLevels();
        for (int i = 0; i <= level_info; i++)
        {
            block_info = this->index.getBlock(i, key);
            if (block_info != "") // Key might be present, however verify if key exists if not check other levels
            {
                CapsuleBlock* block;
                readIn(block_info, block);
                for (long unsigned int j = 0; j < block->kvPairs.size(); j++) 
                {
                    std::tuple<std::string, std::string, int, std::string> kv_tuple = block->kvPairs[j];
                    if (i != 0 && std::get<0>(kv_tuple) > key) 
                    {
                        break;
                    } else if (std::get<0>(kv_tuple) == key) 
                    {
                        return std::get<1>(kv_tuple);
                    } 

                }

                // Saving old code
                // CapsuleIndex::Level &lvls = this.capIndex->levels[i];
                // std::vector<CapsuleIndex::Level>::iterator it = std::find(lvls.recordHashes.begin(), lvls.recordHashes.end(), block_info, != lvls.recordHashes.end());
                // int index = std::distance(lvls.recordHashes.begin(), it);
                // CapsuleBlock &capblock = lvls->block[index];
                // std::vector<CapsuleBlock>::iterator it = std::find(capblock.kvPairs.begin(), capblock.kvPairs.end(), key, != capblock.kvPairs.end());
                // std::tie(k, v, t) = *it;
                // if (key == k)
                //     return v;
            }
        }
        std::cout << "CapsuleDb: Couldn't find key: " << key;
        return "";
    }
    else
        return kv.value;
}
