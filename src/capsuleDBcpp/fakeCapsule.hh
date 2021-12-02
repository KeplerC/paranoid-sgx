#ifndef FAKECAPSULE_H
#define FAKECAPSULE_H

#include <string>
#include "capsuleBlock.hh"

void sha256_string(char *string, char outputBuffer[65]);

std::string putCapsuleBlock(CapsuleBlock inputBlock);

CapsuleBlock getCapsuleBlock(std::string inputHash);

#endif