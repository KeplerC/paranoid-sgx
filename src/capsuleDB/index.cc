/*
 * This file manages and generates new indices for capsuleDB.  It can produce both full and partial indices.
 */

class CapsuleIndex {
    public:
        enum metadata;
        int numLevels;
        bool isFull;
        CapsuleIndex* prevIndex;
        //Lv 0 quocient filter
        //Lv 0 list of hashes
        //Lv 1 quocient filter
        //Lv 1 list of hashes
};