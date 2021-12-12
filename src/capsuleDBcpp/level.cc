#include <string>
#include <tuple>
#include <vector>
#include "../bloom/bloom_filter.hpp"
#include "capsuleBlock.hh"
#include "fakeCapsule.hh"
#include "level.hh"
#include <iostream>

Level::Level() {
    Level(-1, -1);
}

Level::Level(int index, int maxSize) {
    index = index;
    maxSize = maxSize;
    levelFilter = create_filter();

    numBlocks = 0;
    min_key = "";
    max_key = "";
}

bloom_filter Level::create_filter() {
    bloom_parameters params;
    params.projected_element_count = 750000;
    params.false_positive_probability = 0.05;
    params.compute_optimal_parameters();
    bloom_filter filter(params);
    return filter;
}

/*
* Returns the number of blocks in this level.
* 
* Output: int representing number of blocks in the level
*/
int Level::getNumBlocks() {
    return numBlocks;
}

/*
* Sets the number of blocks in this level.
*/
void Level::setNumBlocks(int n) {
    numBlocks = n;
}

/*
* Adds a new block to the level.  Generates a quotient filter and logs the
* range of keys in the block as well.
* 
* Input: New CapsuleBlock to be added.
* Output: 0 on success, other int on error.
*/
int Level::addBlock(CapsuleBlock* newBlock, std::string hash) {
    // Add kv pairs in block to bloom filter
    std::vector < std::tuple<std::string, std::string, int, std::string> > kvPairs = newBlock->getKVPairs();
    for (std::tuple<std::string, std::string, int, std::string> kvt : kvPairs) {
        std::string key = std::get<0>(kvt);
        std::cout << "levelFilter.insert " << key << "\n";
        levelFilter.insert(key);
    }

    std::string new_block_min_key = (*newBlock).getMinKey();
    std::string new_block_max_key = (*newBlock).getMaxKey();
    // If level is empty, directly add and return.
    if (min_key == "" || max_key == "") {
        recordHashes.insert(recordHashes.begin(), hash);
        numBlocks++;
        min_key = new_block_min_key;
        max_key = new_block_max_key;
        return 0;
    }

    /*
    TODO: combine and reorganize blocks
    Algorithm: 
    Assume blocks in level are monotonically increasing. We want to insert block with min and max.
    Find block i and j where i < j and i_min < min < i_max and j_min < max < j_max
        Pull in all blocks between i and j, inclusive, dump into giant vector, and insert all kv pairs in block?
    
    */

    for (int i = 0; i < numBlocks; i++) {
        CapsuleBlock* curr_block = getCapsuleBlock(recordHashes[i]);
        if (curr_block->getMinKey() > new_block_max_key) {
            recordHashes.insert(recordHashes.begin() + i, hash);
            numBlocks++;
            min_key = min(std::string(min_key), std::string(new_block_min_key));
            max_key = max(std::string(max_key), std::string(new_block_max_key));
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
std::string Level::getBlock(std::string key) {
    std::cout << "getBlock for key=" << key << "\n";
    std::cout << "min_key=" << min_key << "\n";
    std::cout << "max_key=" << max_key << "\n";
    if (key < min_key || key > max_key) {
        return "";
    }
    // Otherwise search -> is Binary really needed?
    
    for (int i = 0; i < numBlocks; i++) {
        
        CapsuleBlock* curr_block = getCapsuleBlock(recordHashes[i]);
        // TODO: should this be >= 
        if (key < curr_block->getMinKey()) { 
            return recordHashes[i];
        }
    }
    return "";
}
