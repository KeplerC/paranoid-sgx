/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

#include <string>
#include <list>
#include <tuple>
#include "capsuleBlock.cc"

class CapsuleIndex {
    class Level {
        private:
            int numBlocks;
            int maxSize;
            std::list <std::string> recordHashes;
            std::list < std::tuple<int, int> > keyRanges;
            std::list <filter> quotientForLevel;
        
            /*
            * Returns the number of blocks in this level.
            * 
            * Output: int representing number of blocks in the level
            */
            int getNumBlocks() {
                return numBlocks;
            }

            /*
            * Adds a new block to the level.  Generates a quotient filter and logs the
            * range of keys in the block as well.
            * 
            * Input: New CapsuleBlock to be added.
            * Output: 0 on success, other int on error.
            */
            int addBlock(CapsuleBlock* newBlock) {
                return;
            }

            /*
            * Pulls the corresponding for the provided key.  First checks keyRanges to find 
            * the index of the corresponding block.  Then checks the block's quotient filter
            * to estimate membership.  Finally, pulls the relevant block hash.
            * 
            * Input: Desired key
            * Output: The hash which potentially contains the requested key, error code if not present
            */
            std::string getBlock(std::string key) {
                return;
            }
    };

    public:
        int numLevels;
        std::string prevIndexHash;
        std::list <Level> levels;

        /*
         * Returns the number of levels in the database.
         *
         * Output: int which is the number of levels.
         */
        int getNumLevels() {
            return numLevels;
        }

        /*
         * Returns the hash of the block with the requested key on a given level.  
         *
         * Input: Level and key
         * Output: block hash or error code
         */
        std::string getBlock(int level, std::string key) {
            return;
        }
};