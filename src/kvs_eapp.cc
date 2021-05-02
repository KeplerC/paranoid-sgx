 
#include "kvs_eapp.hpp"
#include "kvs_enclave.hpp"
#include "asylo/util/status.h"
#include <mpl/demo/lambda_common.hpp>

asylo::Status start_eapp(asylo::KVSClient *KVS_client, const asylo::EnclaveInput &input){
    
    hello_world::MP_Lambda_Input lambda_input = input.GetExtension(hello_world::lambda_input);
    mpl::demo::AppOptions options(lambda_input);
    options.setKVSClient(KVS_client);

    mpl::demo::runSelectPlanner(options);

    return asylo::Status::OkStatus();
}
