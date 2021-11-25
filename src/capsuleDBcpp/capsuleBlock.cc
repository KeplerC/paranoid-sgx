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
        CapsuleBlock(int l) {
            level = l;
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

        std::vector < std::tuple<std::string, unsigned char[], int> > getKVPairs() {
            return kvPairs;
        }

        /*
         * Set the lower bound of keys in this block
         */
        void setMinKey(std::string k) {
            startKey = k;
        }

        /*
         * Set the upper bound of keys in this block
         */
        void setMaxKey(std::string k) {
            endKey = k;
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

        void addKVPair(std::string key, unsigned char* value, int timestamp) {
            std::tuple<std::string, unsigned char[], int> element;
            element = make_tuple(key, value, timestamp);
            kvPairs.push_back(element);
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

