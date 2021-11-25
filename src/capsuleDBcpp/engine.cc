/*
 * This file manages the database as well as read/write requests.  
 */

#include <fstream>
#include <string>
#include "../memtable.hpp"

using namespace asylo;

/*
 * This function creates a new CapsuleDB instance.  It takes in information about the sizes of levels and other metadata to establish compaction rules.
 * 
 * Inputs: ???
 * Outputs: An error code
 */
int spawnDB() {
    
    return 0;
}


/*
 * This function connects to a CapsuleDB instance.
 * 
 * Input: None
 * Output: An error code
 */
int connectDB() {
    return 0;
}


/*
 * This function takes in a key-value pair and writes it to CapsuleDB
 *
 * Input: A KV pair
 * Output: Nothing
 */
void put(std:string key, char* value) {
    return "Temp";
}

/* 
 * This function retrieves a key from CapsuleDB.  It queries the DataCapsule for the most recent index and then traverses the DataCapsule to find the requested key.
 * It returns the value either directly to the requesting enclave or multicasts it depending on selected mode.
 *
 * Inputs: The key whose value is requested, the requesting enclave, and a return mode.
 * Output: The requested value or an error if the key does not exist.
 */
char* get(std:string key, Enclave requester, bool isMulticast) {
    return 0;
}
