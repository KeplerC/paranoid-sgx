/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <cstdint>

#include "absl/strings/str_cat.h"
// #include "absl/container/flat_hash_map.h"

#include "asylo/trusted_application.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "src/hello.pb.h"
#include "gdp.h"
#include "memtable.hpp"
#include "hot_msg_pass.h"

class KVSApplication : public asylo::TrustedApplication {
 public:
  KVSApplication() : visitor_count_(0) {}

  void EnclaveMsgStartResponder( HotMsg* hotmsg ) {
    HotMsg_waitForCall( hotmsg );
}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {

    if (input.HasExtension(hello_world::enclave_responder)) {
      printf("[Enclave Responder]\n");

      HotMsg* hotmsg = (HotMsg*) input.GetExtension(hello_world::enclave_responder).responder();
      EnclaveMsgStartResponder( hotmsg );
      return asylo::Status::OkStatus();
    }

    
    //Check if DataCapsule is defined in proto-buf messsage. 
    if (!input.HasExtension(hello_world::dc)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a DataCapsule extension on input.");
    }

    data_capsule_t *ret;
    data_capsule_t *dc = (data_capsule_t *) input.GetExtension(hello_world::dc).dc_ptr();

    LOG(INFO) << "Received DataCapsule id: " << (int) dc->id;
    LOG(INFO) << "DataCapsule payload: " << dc->payload;

    for(data_capsule_id i = 0; i < 300; i++){
      dc->id = i; 
      put(dc);
    }

    for(data_capsule_id i = 0; i < 300; i++){
      ret = get(i);

      if(!ret){
        LOG(INFO) << "GET FAILED on DataCapsule id: " << (int) i;
      }
    }

    LOG(INFO) << "Hashmap size has size: " << memtable.getSize(); 

    std::string visitor =
        input.GetExtension(hello_world::enclave_input_hello).to_greet();

    LOG(INFO) << "Hello " << visitor;

    if (output) {
      LOG(INFO) << "Incrementing visitor count...";
      output->MutableExtension(hello_world::enclave_output_hello)
          ->set_greeting_message(
              absl::StrCat("Hello ", visitor, "! You are visitor #",
                           ++visitor_count_, " to this enclave."));
    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
  MemTable memtable;

  /* These functions willl be part of the CAAPI */
  bool put(data_capsule_t *dc) {
    return memtable.put(dc);
  }

  data_capsule_t *get(data_capsule_id id){
    return memtable.get(id);
  }

};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new KVSApplication; }

}  // namespace asylo
