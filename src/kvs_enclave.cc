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

class HelloApplication : public asylo::TrustedApplication {
 public:
  HelloApplication() : visitor_count_(0) {}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (!input.HasExtension(hello_world::enclave_input_hello)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a HelloInput extension on input.");
    }

    //Check if DataCapsule is defined in proto-buf messsage. 
    if (!input.HasExtension(hello_world::dc)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a DataCapsule extension on input.");
    }

    data_capsule_t *ret;
    data_capsule_t *dc = (data_capsule_t *) input.GetExtension(hello_world::dc).dc_ptr();

    LOG(INFO) << "Received DataCapsule is " << (int) dc->id << ", should be 2021!";
    LOG(INFO) << "DataCapsule payload is " << dc->payload << ", should be 'Hello World!"; 

    for(data_capsule_id i = 0; i < 300; i++){
      dc->id = i; 
      memtable.put(dc);
    }

    for(data_capsule_id i = 0; i < 300; i++){
      ret = memtable.get(i);

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
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
