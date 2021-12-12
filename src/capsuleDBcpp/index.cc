/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

#include <string>
#include <tuple>
#include <cmath>
#include <vector>
#include "../bloom/bloom_filter.hpp"
#include "capsuleBlock.hh"
#include "index.hh"
#include "level.hh"
#include <iostream>

CapsuleIndex::CapsuleIndex() {
    CapsuleIndex(-1);
}

CapsuleIndex::CapsuleIndex(size_t size) {
    numLevels = 1;
    blocksize = size;
    // TODO: prevIndexHash???
    Level level_zero = Level(0, 1);
    levels = {level_zero};
}

/*
* Returns the number of levels in the database.
*
* Output: int which is the number of levels.
*/
int CapsuleIndex::getNumLevels() {
    return numLevels;
}

/*
    * Returns the hash of the block with the requested key on a given level.  
    *
    * Input: Level and key
    * Output: block hash or error code
    */
std::string CapsuleIndex::getBlock(int level, std::string key) {
    std::cout << "getBlock on level=" << level << " for key=" << key << "\n";
    if (level < 0 || level >= numLevels) {
        return "";
    }
    Level curr_level = levels[level];
    if (curr_level.levelFilter.contains(key)) {
        return curr_level.getBlock(key);
    }
    return "";
}

int CapsuleIndex::add_hash(int level, std::string hash, CapsuleBlock block) {
    if (level < 0 || level >= numLevels) {
        return -1;
    }
    int status = levels[level].addBlock(&block, hash);
    compact(level);
    return status;
}

/* 
    * Creates a new level and appends it to the index.
    * 
    * Input: Size of the level (Stored in vector in capsuledb.cc)
    * Output: Returns the index of the new level.
    */
int CapsuleIndex::addLevel(int size) {
    Level newLevel;
    newLevel.numBlocks = 0;
    newLevel.maxSize = size;
    newLevel.index = numLevels;
    
    newLevel.levelFilter = newLevel.create_filter();

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
int CapsuleIndex::compact(int level) {
    
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
            CapsuleBlock* curr_block;
            readIn(curr_block_hash, curr_block);

            std::vector < std::tuple<std::string, std::string, int, std::string> > kvPairs = curr_block->getKVPairs();
            for (std::tuple<std::string, std::string, int, std::string> kvt : kvPairs) {
                std::string key = std::get<0>(kvt);
                std::string value = std::get<1>(kvt);
                int timestamp = std::get<2>(kvt);
                std::string msgType = std::get<3>(kvt);
                
                // find appropriate block in next level
                CapsuleBlock* next_block = find_containing_block(key, level + 1);
                next_block->addKVPair(key, value, timestamp, msgType);
                std::string hash = next_block->writeOut();
                curr_level.recordHashes[i] = hash;
            }
        }

        // wipe current level - delete capsule blocks and reset bloom filter
        // TODO: how does deletion work in DataCapsule?
        curr_level.setNumBlocks(0);
        curr_level.recordHashes.clear();
        curr_level.min_key = "";
        curr_level.max_key = "";
        curr_level.levelFilter = curr_level.create_filter();

        // recursively check for compaction at next level
        compact(level + 1);
    }

    return 0;
}

// optional TODO: binary search
// TODO: how to add new blocks if all blocks in level are full? do we have to redistribute all the kv pairs?
CapsuleBlock* CapsuleIndex::find_containing_block(std::string key, int level) {
    Level containing_level = (*this).levels[level];
    for (int i = 0; i < containing_level.numBlocks; i++) {
        std::string curr_block_hash = containing_level.getBlock(containing_level.recordHashes[i]);
        
        // call function to query DataCapsule for block with hash

        CapsuleBlock* curr_block;
        readIn(curr_block_hash, curr_block);

        if (i == containing_level.numBlocks - 1 || key.compare(curr_block->getMaxKey()) <= 0) {
            return curr_block;
        }
    }
    return NULL;
}
