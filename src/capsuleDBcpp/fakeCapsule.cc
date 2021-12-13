#include <string>
#include <fstream>
#include <openssl/sha.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <sstream>
#include "capsuleBlock.hh"
#include "fakeCapsule.hh"
#include <iostream>

void sha256_string(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

std::string putCapsuleBlock(CapsuleBlock inputBlock) {
    std::cout << "0" << "\n";
    // Serialize Block
    char * serializedBlock;
    std::stringstream toBeHashed;
    boost::archive::text_oarchive testAr(toBeHashed);
    std::cout << "1" << "\n";

    // Hash bytestream
    char blockHash[65];
    std::cout << "1.1" << "\n";
    toBeHashed >> serializedBlock;
    std::cout << "1.2" << "\n";
    sha256_string(serializedBlock, blockHash);

    std::cout << "2" << "\n";
    // Serialize and store block
    std::ofstream storedBlock(blockHash);
    boost::archive::text_oarchive oa(storedBlock);
    oa << inputBlock;

    std::cout << "3" << "\n";
    // Return Hash
    return blockHash;
}

CapsuleBlock getCapsuleBlock(std::string inputHash) {
    CapsuleBlock recoveredBlock;
    // Retrieve and deserialize block
    std::ifstream storedBlock(inputHash);
    boost::archive::text_iarchive ia(storedBlock);
    ia >> recoveredBlock;

    // Check Hash
    char * serializedBlock;
    std::stringstream toBeHashed;
    boost::archive::text_oarchive testAr(toBeHashed);
    testAr << recoveredBlock;
    toBeHashed >> serializedBlock;
    
    char blockHash[65];
    toBeHashed >> serializedBlock;
    sha256_string(serializedBlock, blockHash);
    if (blockHash != inputHash) {
        throw std::invalid_argument("inputHash not found");
    }

    // Return to user
    return recoveredBlock;
}
