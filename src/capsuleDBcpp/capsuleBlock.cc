/* 
 * This file defines a block of key-value pairs which is stored in a DataCapsule.  
 */

#include <string>
#include <vector>
#include <tuple>

class CapsuleBlock {
    private:
        int level;
        std::string startKey;  // Defines the range of keys contained in this block
        std::string endKey;
        std::vector < std::tuple<std::string, unsigned char[], int> > kvPairs;  // Key, value, timestamp
    
    public:
        CapsuleBlock(int l, std::string sk, std::string ek) {
            level = l;
            startKey = sk;
            endKey = ek;
        }
        /*
         * Returns the level of the capsule block
         *
         * Output: int representing the block's level
         */
        int getLevel() {
            return level;
        }
        
        /*
         * Return the lower bound of keys in this block
         *
         * Output: int representing the lowest key in the block
         */
        std::string getMinKey() {
            return startKey;
        }

        /*
         * Return the upper bound of keys in this block
         *
         * Output: int representing the highest key in the block
         */
        std::string getMaxKey() {
            return endKey;
        }

        /*
         * This function takes a prepared block and pushes it to the DataCapusle.
         *
         * Input: None
         * Output: DataCapsule record hash.
         */
        std::string writeOut() {
            return;
        }

        /*
         * This function reads in a data block from the DataCapusle.
         * 
         * Input: Transaction hash of the requested block and the memory location for the record to be stored.
         * Output: Error code or 0 on success.
         */
        void readIn(std::string transactionHash, CapsuleBlock* location) {
            return;
        }
};

