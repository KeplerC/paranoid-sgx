#include <string>
#include <vector>
#include <tuple>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#ifndef CAPSULEBLOCK_H
#define CAPSULEBLOCK_H

class CapsuleBlock {
    private:
        int level;
        
        std::string startKey; // Defines the range of keys contained in this block
        std::string endKey;
        std::vector<std::tuple<std::string, std::string, int, std::string>> kvPairs; // Key, value, timestamp, msgType

        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive & ar, const unsigned int version) {
            ar & level;
            ar & startKey;
            ar & endKey;
            ar & kvPairs;
        }

    public:
        CapsuleBlock(){}
        CapsuleBlock(int l)
        {
            level = l;
        }
        int getLevel();
        std::string getMinKey();
        std::string getMaxKey();
        std::vector<std::tuple<std::string, std::string, int, std::string> > getKVPairs();
        void setMinKey(std::string k);
        void setMaxKey(std::string k);
        std::string writeOut();
        void addKVPair(std::string key, std::string value, int timestamp, std::string msgType);
        void readIn(std::string transactionHash, CapsuleBlock *location);
};

#endif