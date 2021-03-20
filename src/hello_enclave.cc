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
 We assume dc is provided by cliet enclave application 
*/
bool MemTable:: put(data_capsule_t *dc){
  
  uint32_t mem_idx = hash(dc->id);

  if(memtable[mem_idx].buckets.length() >= BUCKET_NUM){
    memtable[mem_idx].buckets.delete_back();
    memtable[mem_idx].buckets.insert_front(dc);
  } else {
    memtable[mem_idx].buckets.insert_front(dc); 
    printf("Inserting in index: %d!\n", mem_idx);
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

    data_capsule_t dc;
    data_capsule_t *ret;

    dc.id = 2021; 
    dc.payload_size = 13; 
    memcpy(dc.payload, "Hello World!", dc.payload_size); 

    memtable.put(&dc);

    LOG(INFO) << dc.payload_size;

    ret = memtable.get(dc.id);

    if(!ret){
      LOG(INFO) << "PUT FAILED!";
      return asylo::Status::OkStatus();
    }

    printf("ret: %p\n", ret);

    std::string visitor =
        input.GetExtension(hello_world::enclave_input_hello).to_greet();

    LOG(INFO) << "Hello " << visitor;
    LOG(INFO) << "Hashmap size: " << memtable.getSize() << " ret: id " << ret->payload_size;
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
