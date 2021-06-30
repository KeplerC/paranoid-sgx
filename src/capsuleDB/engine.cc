/*
 * This file manages the database as well as read/write requests.  
 */

#include <string>

using namespace std;

/*
 * This function takes in a filled memtable, converts it to capsuleBlock format, and writes it to the DataCapsule.
 *
 * Input: A filled Memtable
 * Output: The hash(es) of the DataCapsule transactions
 */
string put(Memtable newMemtable) {
    return "Temp";
}

/* 
 * This function retrieves a key from CapsuleDB.  It queries the DataCapsule for the most recent index and then traverses the DataCapsule to find the requested key.
 * It returns the value either directly to the requesting enclave or multicasts it depending on selected mode.
 *
 * Inputs: The key whose value is requested, the requesting enclave, and a return mode.
 * Output: The requested value or an error if the key does not exist.
 */
int* get(int key, Enclave requester, bool isMulticast) {
    return 0;
}

/*
 * This function checks a level to see whether it has overflowed.  If so, then it triggers compaction at that level.
 *  
 * Input: A level to check
 * Output: True if compaction is needed, false otherwise.
 */
void checkCompaction (int level) {
    return;
}