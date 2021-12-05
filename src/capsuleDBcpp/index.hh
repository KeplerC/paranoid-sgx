#include <string>
#include <vector>
#include "capsuleBlock.hh"

class CapsuleIndex {
    public:
        int numLevels;
        int blocksize;
        std::string prevIndexHash;
        std::vector <Level> levels;

        
        int getNumLevels();
        std::string getBlock(int level, std::string key);
        int add_hash(int level, std::string hash, CapsuleBlock block);
        int addLevel(int size);
        int compact(int level);
        CapsuleBlock find_containing_block(std::string key, int level);
};