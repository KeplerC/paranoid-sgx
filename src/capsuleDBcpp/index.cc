/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

#include <string>
#include <list>
#include <tuple>
#include "capsuleBlock.cc"
#include "../bloom/bloom_filter.hpp"

class CapsuleIndex {
    class Level {
        public:
            int numBlocks;
            int maxSize;
            std::string min_key;
            std::string max_key;
            std::vector <std::string> recordHashes;
            std::vector <CapsuleBlock> blocks; 
            bloom_filter levelFilter;
        
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
            int addBlock(CapsuleBlock* newBlock, std::string hash) {
                std::vector<CapsuleBlock>::iterator iter;
                for (int i = 0; i < numBlocks; i++) {
                    CapsuleBlock curr_block = blocks[i];
                    if (curr_block.getMinKey() > (*newBlock).getMaxKey()) {
                        blocks.insert(blocks.begin() + i, *newBlock);
                        recordHashes.insert(recordHashes.begin() + i, hash);
                        numBlocks++;
                        if (numBlocks * blocksize > maxSize) {
                            // trigger compaction
                        }
                        return 0;
                    }
                }
                return -1;
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
                if (key < min_key || key > max_key) {
                    return NULL;
                }
                // Otherwise search -> is Binary really needed?
                
                for (int i = 0; i < numBlocks; i++) {
                    CapsuleBlock curr_block = blocks[i];
                    if (key < curr_block.getMinKey()) {
                        return recordHashes[i];
                    }
                }

                return NULL;
            }
    };

    public:
        int numLevels;
        std::string prevIndexHash;
        std::vector <Level> levels;

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
            if (level < 0 || level >= numLevels) {
                return NULL;
            }
            Level curr_level = levels[level];
            if (curr_level.levelFilter.contains(key)) {
                return curr_level.getBlock(key);
            }
            return NULL;
        }

        int add_hash(int level, std::string hash, CapsuleBlock block) {
            if (level < 0 || level >= numLevels) {
                return NULL;
            }
            return levels[level].addBlock(&block, hash);
        }

        /* 
         * Creates a new level and appends it to the index.
         * 
         * Input: None
         * Output: Returns the index of the new level.
         */
        int addLevel() {
            
        }
};