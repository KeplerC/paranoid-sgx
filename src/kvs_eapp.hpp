#pragma once

#include "kvs_enclave.hpp"
#include "asylo/util/status.h"

asylo::Status start_eapp(asylo::KVSClient *KVS_client, const asylo::EnclaveInput &input);