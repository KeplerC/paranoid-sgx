/*
 * This file manages the database as well as read/write requests.  
 */

#include <fstream>
#include <string>
#include "memtable_new.hpp"
#include "../common.h"
#include "capsuledb.hh"

// using namespace asylo;

/*
 * This function creates a new CapsuleDB instance.  It takes in information about the sizes of levels and other metadata to establish compaction rules.
 * 
 * Inputs: ???
 * Outputs: An error code
 */
int spawnDB();
int connectDB();
void CapsuleDB::put(const kvs_payload *payload);
char *CapsuleDB::get(const std::string &key, Enclave requester, bool isMulticast = false);