#include <string>
#include "capsuleBlock.cc"
#include <openssl/sha.h>
#include <fstream>

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
    // Serialize Block
    char blockToStore[65];
    
    // Hash bytestream
    char blockHash[65];
    sha256_string(blockToStore, blockHash);

    // Send to disk
    ofstream storedBlock;
    storedBlock.open(blockHash);
    storedBlock << blockToStore;
    storedBlock.close();

    // Return Hash
    return blockHash
}

CapsuleBlock getCapsuleBlock(std::string inputHash) {
    // Get bytestream from disk
    char storedBlockData[65];
    ifstream storedBlock;
    storedBlock.open(inputHash);
    storedBlock >> storedBlockData;
    storedBlock.close();

    // Check hash match
    char computedHash[65];
    sha256_string(storedBlockData, computedHash);
    if (computedHash != inputHash) {
        return NULL;
    }

    // Deserialize

    CapsuleBlock recoveredBlock;

    // Return to user
    return recoveredBlock;
}