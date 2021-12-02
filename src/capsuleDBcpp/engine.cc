/*
 * This file manages the database as well as read/write requests.  
 */

#include <fstream>
#include <string>
#include "memtable_new.hpp"
#include "../common.h"

// using namespace asylo;

/*
 * This function creates a new CapsuleDB instance.  It takes in information about the sizes of levels and other metadata to establish compaction rules.
 * 
 * Inputs: ???
 * Outputs: An error code
 */
int spawnDB()
{

    return 0;
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
    if (!memtable->put(payload))
    {
        LOGI << "Failed to write key in the Database";
    }
}

/* 
 * This function retrieves a key from CapsuleDB.  It queries the DataCapsule for the most recent index and then traverses the DataCapsule to find the requested key.
 * It returns the value either directly to the requesting enclave or multicasts it depending on selected mode.
 *
 * Inputs: The key whose value is requested, the requesting enclave, and a return mode.
 * Output: The requested value or an error if the key does not exist.
 */
char *CapsuleDB::get(const std::string &key, Enclave requester, bool isMulticast = false)
{
    int level_info;
    kvs_payload kv = memtable->get(key);
    std::string block_info, k;
    unsigned char v[];
    int t;

    if (kv.key == "") //Checks for key in memtable, if not present: checks in levels
    {
        // TODO iterate if there are multiple capsule indices
        level_info = capIndex->getNumLevels();
        for (int i = 0; i <= level_info; i++)
        {
            block_info = capIndex->getblock(i, key);
            if (block_info != NULL) // Key might be present, however verify if key exists if not check other levels
            {
                CapsuleIndex::Level &lvls = capIndex->levels[i];
                std::vector<CapsuleIndex::Level>::iterator it = std::find(lvls.recordHashes.begin(), lvls.recordHashes.end(), block_info, != lvls.recordHashes.end());
                int index = std::distance(lvls.recordHashes.begin(), it);
                CapsuleBlock &capblock = lvls->block[index];
                std::vector<CapsuleBlock>::iterator it = std::find(capblock.kvpairs.begin(), capblock.kvpairs.end(), key, != capblock.kvpairs.end());
                std::tie(k, v, t) = *it;
                if (key == k)
                    return v;
            }
        }
        if ((i == level_info) || (block_info == NULL))
        {
            LOGI << "CapsuleDb: Couldn't find key: " << key;
            return "";
        }
    }
    else
        return &kv.value;
}
