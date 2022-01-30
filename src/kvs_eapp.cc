 
#include "kvs_eapp.hpp"
#include "kvs_enclave.hpp"
#include "asylo/util/status.h"
#include <mpl/demo/lambda_common.hpp>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

asylo::Status start_eapp(asylo::KVSClient *KVS_client, const asylo::EnclaveInput &input){
    hello_world::MP_Lambda_Input lambda_input = input.GetExtension(hello_world::lambda_input);
    mpl::demo::AppOptions options(lambda_input);

    const char *homedir;

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }

    static const std::string resourceDirectory = std::string(homedir) + "/paranoid-sgx/src/mplambda/resources/";

    options.setKVSClient(KVS_client);
    options.timeStart = lambda_input.time_start(); 

    if (!options.env_.empty())
        options.env_ = resourceDirectory + options.env_;
    if (!options.robot_.empty())
        options.robot_ = resourceDirectory + options.robot_;

    mpl::demo::runSelectPlanner(options);
    return asylo::Status::OkStatus();
}
