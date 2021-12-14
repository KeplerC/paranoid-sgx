#ifndef INDEX_H
#define INDEX_H

#include <string>
#include <vector>
#include "capsuleBlock.hh"
#include "level.hh"

class CapsuleIndex {
    public:
        int numLevels;
        size_t blocksize;
        std::string prevIndexHash;
        std::vector <Level> levels;
        
        CapsuleIndex();
        CapsuleIndex(size_t size);
        int getNumLevels();
        std::string getBlock(int level, std::string key);
        int add_hash(int level, std::string hash, CapsuleBlock block);
        int addLevel(int size);
        int compact(int level);
        int capsuleHelper(int sourceLevel, int destLevel);
        CapsuleBlock* find_containing_block(std::string key, int level);
};

#endif