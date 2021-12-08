#include <string>
#include <tuple>
#include <vector>
#include "../bloom/bloom_filter.hpp"
#include "capsuleBlock.hh"
#include "fakeCapsule.hh"
#include "level.hh"


bloom_filter create_filter() {
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
    std::vector<CapsuleBlock>::iterator iter;
    if (min_key == "") {
        min_key = (*newBlock).getMinKey();
    }
    if (max_key == "") {
        max_key = (*newBlock).getMaxKey();
    }
    min_key = min(std::string(min_key), std::string((*newBlock).getMinKey()));
    max_key = max(std::string(max_key), std::string((*newBlock).getMaxKey()));
    for (int i = 0; i < numBlocks; i++) {
        CapsuleBlock* curr_block = getCapsuleBlock(recordHashes[i]);
        if (curr_block->getMinKey() > (*newBlock).getMaxKey()) {
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
std::string Level::getBlock(std::string key) {
    if (key < min_key || key > max_key) {
        return NULL;
    }
    // Otherwise search -> is Binary really needed?
    
    for (int i = 0; i < numBlocks; i++) {
        CapsuleBlock* curr_block = getCapsuleBlock(recordHashes[i]);
        if (key < curr_block->getMinKey()) {
            return recordHashes[i];
        }
    }

    return NULL;
}
