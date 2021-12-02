/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

#include <string>
#include <list>
#include <tuple>
// TODO: Add bloom filter
#include "../bloom/bloom_filter.hpp"
#include <cmath>
#include <vector>
#include "capsuleBlock.cc"

class CapsuleIndex {
    class Level {
        private:
            bloom_filter create_filter() {
                bloom_parameters params;
                params.projected_element_count = 750000;
                params.false_positive_probability = 0.05;
                params.compute_optimal_parameters();
                bloom_filter filter(params);
                return filter;
            }
        public:
            int index;
            int numBlocks;
            int maxSize;
            std::string min_key;
            std::string max_key;
            std::vector <std::string> recordHashes;
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
            * Sets the number of blocks in this level.
            */
            void setNumBlocks(int n) {
                numBlocks = n;
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
                if (!min_key) {
                    min_key = (*newBlock).getMinKey();
                }
                if (!max_key) {
                    max_key = (*newBlock).getMaxKey();
                }
                min_key = min(std::string(min), std::string((*newBlock).getMinKey()));
                max_key = max(std::string(max), std::string((*newBlock).getMaxKey()));
                for (int i = 0; i < numBlocks; i++) {
                    CapsuleBlock curr_block = blocks[i];
                    if (curr_block.getMinKey() > (*newBlock).getMaxKey()) {
                        blocks.insert(blocks.begin() + i, *newBlock);
                        recordHashes.insert(recordHashes.begin() + i, hash);
                        numBlocks++;
                        compact(index);
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
         * Input: Size of the level (Stored in vector in capsuledb.cc)
         * Output: Returns the index of the new level.
         */
        int addLevel(int size) {
            Level newLevel;
            newLevel.numBlocks = 0;
            newLevel.maxSize = size;
            newLevel.index = numLevels;
            
            newLevel.levelFilter = create_filter();

            numLevels++;
            return numLevels - 1; 
        }

        /*
        * This function manages the compaction process.  It assumes that compaction is needed and does not check the size of the level.
        * It wil recursively handle further compactions if necessary.
        * 
        * Input: Level to compact.
        * Output: Error code or 0 on success.
        */
        int compact(int level) {
            
            /*
            pseudocode:
            For every Capsule Block at current level (iterate in order of oldest to newest):
                For every key in Capsule Block:
                    Put key into an appropriate Capsule Block in next level (do we need binary search?)
            Delete all Capsule Blocks from current level
            */

            if (level < 0 || level >= numLevels) {
                return -1;
            }

            // if we need to compact the last level, create a new level under it 10 times as large
            if (level == numLevels - 1) {
                addLevel(24 * pow(10, numLevels)); 
            }

            Level curr_level = levels[level];

            // compaction trigger condition
            if (curr_level.numBlocks * blocksize > curr_level.maxSize) {
                for (int i = 0; i < curr_level.numBlocks; i++) {
                    std::string curr_block_hash = curr_level.getBlock(curr_level.recordHashes[i]);
                    
                    // call function to query DataCapsule for block with hash
                    CapsuleBlock curr_block = getCapsuleBlock(curr_block_hash);

                    std::vector < std::tuple<std::string, unsigned char[], int> > kvPairs = curr_block.getKVPairs();
                    for (std::tuple<std::string, unsigned char[], int> kvt : kvPairs) {
                        std::string key = std::get<0>(kvt);
                        unsigned char* value = std::get<1>(kvt);
                        int timestamp = std::get<2>(kvt);
                        
                        // find appropriate block in next level
                        CapsuleBlock next_block = find_containing_block(key, level + 1);
                        next_block.addKVPair(key, value, timestamp);
                        std::string hash = putCapsuleBlock(next_block);
                        recordHashes[i] = hash;
                    }
                }

                // wipe current level - delete capsule blocks and reset bloom filter
                // TODO: how does deletion work in DataCapsule?
                curr_level.setNumBlocks(0);
                curr_level.recordHashes = NULL;
                curr_level.min_key = NULL;
                curr_level.max_key = NULL;
                curr_level.levelFilter = create_filter()

                // recursively check for compaction at next level
                compact(level + 1);
            }

            return 0;
        }

        // optional TODO: binary search
        // TODO: how to add new blocks if all blocks in level are full? do we have to redistribute all the kv pairs?
        CapsuleBlock find_containing_block(std::string key, int level) {
            Level level = levels[level];
            for (int i = 0; i < level.numBlocks; i++) {
                std::string curr_block_hash = level.getBlock(level.recordHashes[i]);
                
                // call function to query DataCapsule for block with hash
                CapsuleBlock curr_block = getCapsuleBlock(curr_block_hash);

                if (i == level.numBlocks - 1 || key.compare(curr_block.getMaxKey()) <= 0) {
                    return curr_block;
                }
            }
            
        }
};
