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
    Level level_zero = Level(0, 4);
    Level level_one = Level(1, 40);
    levels.push_back(level_zero);
    levels.push_back(level_one);
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
    // if (curr_level.levelFilter.contains(key)) {
    //     return curr_level.getBlock(key);
    // }
    // return "";
    return curr_level.getBlock(key);
}

int CapsuleIndex::add_hash(int level, std::string hash, CapsuleBlock block) {
    if (level < 0 || level >= numLevels) {
        return -1;
    }
    int status = levels[level].addBlock(&block, hash);
    compact();
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
    
    // newLevel.levelFilter = newLevel.create_filter();

    numLevels++;
    return numLevels - 1; 
}

/*
* This function manages the compaction process by performing initial comapction determinations at L0
* Further compactions and the actual compaction logic is handled in compactHelper.  
* 
* Input: Level to compact.
* Output: Error code or 0 on success.
*/
int CapsuleIndex::compact() {
    Level* lv0 = &levels.front();

    std::cout << "ENTERING compact()\n";

    if (blocksize * lv0->numBlocks < lv0->maxSize) {
        return 0;
    }

    std::cout << "recordHashes.size()=" << lv0->recordHashes.size() << "\n";
    std::cout << "recordHashes[0].minKey=" << lv0->recordHashes[0].minKey << "\n";
    std::cout << "recordHashes[0].maxKey=" << lv0->recordHashes[0].maxKey << "\n";
    std::cout << "recordHashes[1].minKey=" << lv0->recordHashes[1].minKey << "\n";
    std::cout << "recordHashes[1].maxKey=" << lv0->recordHashes[1].maxKey << "\n";

    // Sort vectors in each block of L0
    sortL0();

    // Sort L0
    std::vector<blockHeader> sortedLv0;
    sortedLv0.push_back(lv0->recordHashes[0]);
    for (int i = 1; i < lv0->recordHashes.size(); i++) {
        std::vector<blockHeader> currBlock;
        currBlock.push_back(lv0->recordHashes[i]);
        sortedLv0 = merge(sortedLv0, currBlock, 0);
    }

    std::cout << "sortedLv0.size()=" << sortedLv0.size() << "\n";
    std::cout << "sortedLv0[0].minKey=" << sortedLv0[0].minKey << "\n";
    std::cout << "sortedLv0[0].maxKey=" << sortedLv0[0].maxKey << "\n";
    std::cout << "sortedLv0[1].minKey=" << sortedLv0[1].minKey << "\n";
    std::cout << "sortedLv0[1].maxKey=" << sortedLv0[1].maxKey << "\n";

    if (numLevels == 1) {
        addLevel(10 * lv0->maxSize);
    }

    compactHelper(sortedLv0, &(levels[1]));    
    std::cout << "Size of L1 after return from compactHelper=" << levels[1].recordHashes.size() << "\n";
    std::cout << "Size of L1 after return from compactHelper=" << levels[1].min_key << "\n";
    lv0->recordHashes.clear();
    lv0->numBlocks = 0;
    lv0->min_key = "";
    lv0->max_key = "";

    return 0;
}

/* 
 * This function merges blocks into exisiting levels.  It also determines whether doing so would cause an overflow.
 * If so, it recursively compacts by identifying which blocks are modified in destLevel and pushing them into the level
 * below.
 * 
 * Input: A sorted vector of blockHeaders sourceVec, the level the vector is being compacted into destLevel.
 * Output: 0 if no error, other number otherwise
 */

int CapsuleIndex::compactHelper(std::vector<blockHeader> sourceVec, Level *destLevel) {
    
    std::cout << "ENTERING compactHelper()\n";
    std::cout << "sourceVec.size()=" << sourceVec.size() << "\n";
    std::cout << "destLevel.recordHashes.size()=" << destLevel->recordHashes.size() << "\n";
    std::cout << "destLevel.maxSize=" << destLevel->maxSize << "\n";
 
    if (blocksize * sourceVec.size() + blocksize * destLevel->recordHashes.size() >= destLevel->maxSize) {
        // Identify Affected blocks
        std::vector<blockHeader> newSourceVec;
        std::vector<blockHeader> remainingBlocks;
        blockHeader currBlock;
        int destInd = 0;
        blockHeader lastAdded;
        for (int i = 0; i < sourceVec.size(); i++) {
            currBlock = sourceVec[i];
            while (destInd < destLevel->recordHashes.size()) {
                blockHeader currExamining = destLevel->recordHashes[destInd];
                if (currBlock.minKey >= currExamining.minKey && currBlock.minKey <= currExamining.maxKey && currExamining.hash != lastAdded.hash) {
                    newSourceVec.push_back(currExamining);
                    lastAdded = currExamining;
                } else if (currBlock.maxKey >= currExamining.minKey && currBlock.maxKey <= currExamining.maxKey && currExamining.hash != lastAdded.hash) {
                    newSourceVec.push_back(currExamining);
                    lastAdded = currExamining;
                    break;
                } else if (currExamining.hash != lastAdded.hash) {
                    remainingBlocks.push_back(currExamining);
                    break;
                }
                destInd++;
            }
        }
        if (destLevel->index + 1 >= numLevels) {
            addLevel(destLevel->maxSize * 10);
        }
        compactHelper(newSourceVec, &(levels[destLevel->index]));
        destLevel->recordHashes = remainingBlocks;
        destLevel->numBlocks = remainingBlocks.size();
        destLevel->min_key = remainingBlocks[0].minKey;
        destLevel->max_key = remainingBlocks[remainingBlocks.size() - 1].maxKey;

    }
    
    std::vector<blockHeader> newDestLevelVec = merge(sourceVec, destLevel->recordHashes, destLevel->index);
    destLevel->recordHashes = newDestLevelVec;
    destLevel->numBlocks = newDestLevelVec.size();
    destLevel->min_key = newDestLevelVec[0].minKey;
    destLevel->max_key = newDestLevelVec[newDestLevelVec.size() - 1].maxKey;
    std::cout << "Size of new L1 vec=" << destLevel->recordHashes.size() << "\n";
    std::cout << "MinKey of new L1=" << destLevel->min_key << "\n";
    return 0;
}

/*
    This function takes in two lists of blockHeaders representing two levels of sorted CapsuleBlocks
    Merges them into a new list of blockHeaders representing a level of sorted CapsuleBlocks.
*/
std::vector<blockHeader> CapsuleIndex::merge(std::vector<blockHeader> a, std::vector<blockHeader> b, int next_level) {
    std::cout << "ENTERING merge()\n";
    
    std::vector<blockHeader> output;
    
    size_t aa = 0;
    size_t bb = 0;
    size_t aaa = 0;
    size_t bbb = 0;

    bool advanceA = false;
    bool advanceB = false;

    blockHeader blockHeaderA = a[aa];
    CapsuleBlock capsuleBlockA;
    readIn(blockHeaderA.hash, &capsuleBlockA);

    blockHeader blockHeaderB;
    CapsuleBlock capsuleBlockB;
    if (b.size() > 0) {
        blockHeaderB = b[bb];
        readIn(blockHeaderB.hash, &capsuleBlockB);
    }
    
    CapsuleBlock next_cb = CapsuleBlock(next_level);

    while (aa != a.size() || bb != b.size()) {

        // Find smallest KV pair by comparing the next KV pair of each level.
        std::tuple<std::string, std::string, int, std::string> nextKVPair;

        // If we've reached the end of either level, use other level.
        if (aa == a.size()) {
            nextKVPair = capsuleBlockB.getKVPairs()[bbb];
            advanceB = true;
        }
        else if (bb == b.size()) {
            nextKVPair = capsuleBlockA.getKVPairs()[aaa];
            advanceA = true;
        } else {
            // If both levels have remaining KV pairs to add, push out the smallest one.
            std::tuple<std::string, std::string, int, std::string> KVPairA = capsuleBlockA.getKVPairs()[aaa];
            std::tuple<std::string, std::string, int, std::string> KVPairB = capsuleBlockB.getKVPairs()[bbb];
            std::string keyA = std::get<0>(KVPairA);
            std::string keyB = std::get<0>(KVPairB);
            if (keyB < keyA) {
                nextKVPair = KVPairB;
                advanceB = true;
            } else if (keyA < keyB) {
                nextKVPair = KVPairA;
                advanceA = true;
            } else {
                // If both KV pairs have the same key, push out the most recent one and disregard the older one.
                int64_t timestampA = std::get<2>(KVPairA);
                int64_t timestampB = std::get<2>(KVPairB);
                if (timestampB >= timestampA) {
                    nextKVPair = KVPairB;
                } else {
                    nextKVPair = KVPairA;
                }
                advanceA = true;
                advanceB = true;
            }
        }    std::cout << "Test";

        
        // Advance pointers for either A or B or both, pulling in next CapsuleBlock if reached end of current one.
        if (advanceA) {
            aaa++;
            if (aaa == capsuleBlockA.getKVPairs().size()) {
                aaa = 0;
                aa++;
                if (aa < a.size()) {
                    blockHeaderA = a[aa];
                    readIn(blockHeaderA.hash, &capsuleBlockA);
                }
            }
        }
        if (advanceB) {
            bbb++;
            if (bbb == capsuleBlockB.getKVPairs().size()) {
                bbb = 0;
                bb++;
                if (bb < b.size()) {
                    blockHeaderB = b[bb];
                    readIn(blockHeaderB.hash, &capsuleBlockB);
                }
            }
        }
        advanceA = false;
        advanceB = false;

        // Add next KV pair to a CapsuleBlock, and write out if full.
        std::cout << "next key=" << std::get<0>(nextKVPair) << "\n";
        next_cb.addKVPair(
            std::get<0>(nextKVPair), 
            std::get<1>(nextKVPair), 
            std::get<2>(nextKVPair), 
            std::get<3>(nextKVPair));
        if (next_cb.getKVPairs().size() == blocksize) {
            std::string hash = next_cb.writeOut();
            blockHeader bh = {};
            bh.hash = hash;
            bh.minKey = next_cb.getMinKey();
            bh.maxKey = next_cb.getMaxKey();
            output.push_back(bh);
            next_cb = CapsuleBlock(next_level);
        }
    }

    // Write out the final CapsuleBlock, even if it's not full.
    if (next_cb.getKVPairs().size() > 0) {
        std::string hash = next_cb.writeOut();
        blockHeader bh = {};
        bh.hash = hash;
        bh.minKey = next_cb.getMinKey();
        bh.maxKey = next_cb.getMaxKey();
        output.push_back(bh);
    }

    return output;
}

/*
 * This function sorts the keys in each individual L0 block.
 *
 * Input: None
 * Output: None
 */
void CapsuleIndex::sortL0() {
    std::cout << "ENTERING sortL0()" << "\n";
    Level* lv0 = &levels.front();
    CapsuleBlock currBlock;
    std::vector<blockHeader> newRecordHashes;
    for (int i = 0; i < lv0->recordHashes.size(); i++) {
        readIn(lv0->recordHashes[i].hash, &currBlock); 
        std::sort(currBlock.kvPairs.begin(), currBlock.kvPairs.end());
        std::string hash = currBlock.writeOut();
        lv0->recordHashes[i].hash = hash;
    }
}