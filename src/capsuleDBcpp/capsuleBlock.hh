#ifndef CAPSULEBLOCK_H
#define CAPSULEBLOCK_H

#include <string>
#include <vector>
#include <tuple>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include "../serialize-tuple/serialize_tuple.h"

typedef struct {
    std::string hash;
    std::string minKey;
    std::string maxKey;
} blockHeader;

class CapsuleBlock {
    private:
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive & ar, const unsigned int version) {
            ar & level;
            ar & startKey;
            ar & endKey;
            ar & kvPairs;
        }

    public:
        int level;
        std::string startKey; // Defines the range of keys contained in this block
        std::string endKey;
        std::vector<std::tuple<std::string, std::string, int, std::string>> kvPairs; // Key, value, timestamp, msgType
        
        CapsuleBlock();
        CapsuleBlock(int l);
        int getLevel();
        std::string getMinKey();
        std::string getMaxKey();
        std::vector<std::tuple<std::string, std::string, int, std::string> > getKVPairs();
        void addKVPair(std::string key, std::string value, int64_t timestamp, std::string msgType);
        void setMinKey(std::string k);
        void setMaxKey(std::string k);
        std::string writeOut();
        void readIn(std::string transactionHash, CapsuleBlock *location);
};

void readIn(std::string transactionHash, CapsuleBlock *location);

#endif