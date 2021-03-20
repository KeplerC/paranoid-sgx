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
#include "double_linked_list.h"

#define MAX_MEM_SZ 300
#define BUCKET_NUM 5

struct bucket_entry{
  bool valid;
  DoublyLinkedList buckets; 
};

class MemTable {
  public:
    size_t getSize(); 
    bool put(data_capsule_t *dc);
    data_capsule_t *get(data_capsule_id id);
    __uint32_t hash(data_capsule_id id);
    MemTable(){
      max_capacity = MAX_MEM_SZ; 
      curr_capacity = 0; 
    }
  private:
    bucket_entry memtable[MAX_MEM_SZ/BUCKET_NUM];
    size_t max_capacity;  
    size_t curr_capacity; 
};

// TODO: Replace hash function
__uint32_t MemTable:: hash(data_capsule_id id){
    return id % (MAX_MEM_SZ/BUCKET_NUM);
}


data_capsule_t *MemTable:: get(data_capsule_id id){

  uint32_t mem_idx = hash(id);

  if(!memtable[mem_idx].buckets.length()){
    printf("Index: %d is invalid!\n", mem_idx);
    return NULL;
  }

  data_capsule_t *ret = memtable[mem_idx].buckets.search(id);
  return ret; 
}


/*
 Datacapsule is copied into memtable  
 We assume dc is provided by client enclave application 
*/
bool MemTable:: put(data_capsule_t *dc){
  
  uint32_t mem_idx = hash(dc->id);

  if(memtable[mem_idx].buckets.length() >= BUCKET_NUM){
    memtable[mem_idx].buckets.delete_back();
    memtable[mem_idx].buckets.insert_front(dc);
  } else {
    memtable[mem_idx].buckets.insert_front(dc); 
    curr_capacity++; 
  }

  return true; 

}

size_t MemTable::getSize() {
  return curr_capacity; 
}

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

    printf("Received DataCapsule is %d, should be 2021!\n", dc->id);
    printf("DataCapsule payload is %s, should be 'Hello World!'\n", dc->payload);

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
