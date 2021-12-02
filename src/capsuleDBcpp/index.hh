/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

#ifndef INDEX_H
#define INDEX_H

#include <string>
#include <list>
#include <tuple>
// TODO: Add bloom filter
#include "../bloom/bloom_filter.hpp"
#include <cmath>
#include <vector>
#include "capsuleBlock.hh"
#include "fakeCapsule.hh"

class CapsuleIndex {
    class Level {
        private:
            bloom_filter create_filter(); 
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
            int getNumBlocks();

            /*
            * Sets the number of blocks in this level.
            */
            void setNumBlocks(int n);

            /*
            * Adds a new block to the level.  Generates a quotient filter and logs the
            * range of keys in the block as well.
            * 
            * Input: New CapsuleBlock to be added.
            * Output: 0 on success, other int on error.
            */
            int addBlock(CapsuleBlock* newBlock, std::string hash);

            /*
            * Pulls the corresponding for the provided key.  First checks keyRanges to find 
            * the index of the corresponding block.  Then checks the block's quotient filter
            * to estimate membership.  Finally, pulls the relevant block hash.
            * 
            * Input: Desired key
            * Output: The hash which potentially contains the requested key, error code if not present
            */
            std::string getBlock(std::string key);
    };

    public:
        int numLevels;
        int blocksize;
        std::string prevIndexHash;
        std::vector <Level> levels;

        /*
         * Returns the number of levels in the database.
         *
         * Output: int which is the number of levels.
         */
        int getNumLevels();

        /*
         * Returns the hash of the block with the requested key on a given level.  
         *
         * Input: Level and key
         * Output: block hash or error code
         */
        std::string getBlock(int level, std::string key);

        int add_hash(int level, std::string hash, CapsuleBlock block);

        /* 
         * Creates a new level and appends it to the index.
         * 
         * Input: Size of the level (Stored in vector in capsuledb.cc)
         * Output: Returns the index of the new level.
         */
        int addLevel(int size);

        /*
        * This function manages the compaction process.  It assumes that compaction is needed and does not check the size of the level.
        * It wil recursively handle further compactions if necessary.
        * 
        * Input: Level to compact.
        * Output: Error code or 0 on success.
        */
        int compact(int level);

        // optional TODO: binary search
        // TODO: how to add new blocks if all blocks in level are full? do we have to redistribute all the kv pairs?
        CapsuleBlock find_containing_block(std::string key, int level) ;
};

#endif
