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


  int HotMsg_requestCall( HotMsg* hotMsg, int dataID, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    int data_index = dataID % (MAX_QUEUE_LENGTH - 1);

    //Request call
    while( true ) {

        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
        sgx_spin_lock( &data_ptr->spinlock );
        // printf("[HotMsg_requestCall] keep polling: %d\n", hotMsg->keepPolling);

        if( data_ptr-> isRead == true ) {
            data_ptr-> isRead  = false;
            data_ptr->data = data;
            data_capsule_t *arg = (data_capsule_t *) data; 
            // printf("[HotMsg_requestCall] data id: %d\n", arg->id);
            sgx_spin_unlock( &data_ptr->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &data_ptr->spinlock );

        numRetries++;
        // if( numRetries > MAX_RETRIES ){
        //     printf("exceeded tries\n");
        //     sgx_spin_unlock( &data_ptr->spinlock );
        //     return -1;
        // }

        for( i = 0; i<3; ++i)
            _mm_sleep();
    }

    return numRetries;
}

  void EnclaveMsgStartResponder( HotMsg *hotMsg )
{
    int dataID = 0;

    static int i;
    sgx_spin_lock(&hotMsg->spinlock );
    hotMsg->initialized = true;  
    sgx_spin_unlock(&hotMsg->spinlock);

    while( true )
    {

      if( hotMsg->keepPolling != true ) {
            break;
      }
      
      HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
      if (data_ptr == 0){
          continue;
      }

      sgx_spin_lock( &data_ptr->spinlock );

      if(data_ptr->data){
          //Message exists!
          data_capsule_t *arg = (data_capsule_t *) data_ptr->data; 
          put(arg);
          printf("Put message: %d\n", arg->id);
          data_ptr->data = 0; 
      }

      data_ptr->isRead      = true;
      sgx_spin_unlock( &data_ptr->spinlock );
      dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
      for( i = 0; i<3; ++i)
          _mm_pause();
  }
}


  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {


    if (input.HasExtension(hello_world::enclave_responder)) {
      printf("[Enclave Responder] Start\n");
      HotMsg* hotmsg = (HotMsg*) input.GetExtension(hello_world::enclave_responder).responder();
      EnclaveMsgStartResponder( hotmsg );
      printf("[Enclave Responder] Finish\n");
      return asylo::Status::OkStatus();
    }

    
    //Check if DataCapsule is defined in proto-buf messsage. 
    if (!input.HasExtension(hello_world::dc)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a DataCapsule extension on input.");
    }

    data_capsule_t *ret;
    data_capsule_t *dc = (data_capsule_t *) input.GetExtension(hello_world::dc).dc_ptr();
    HotMsg *buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();

    data_capsule_t dc_msg;
    dc_msg.id = 1111; 

    for( uint64_t i=0; i < 10; ++i ) {
        HotMsg_requestCall(buffer, 0, &dc_msg);
    }

    // LOG(INFO) << "Received DataCapsule id: " << (int) dc->id;
    // LOG(INFO) << "DataCapsule payload: " << dc->payload;

    // for(data_capsule_id i = 0; i < 300; i++){
    //   dc->id = i; 
    //   put(dc);
    // }

    // for(data_capsule_id i = 0; i < 300; i++){
    //   ret = get(i);

    //   if(!ret){
    //     LOG(INFO) << "GET FAILED on DataCapsule id: " << (int) i;
    //   }
    // }

    LOG(INFO) << "Hashmap size has size: " << memtable.getSize(); 

    // std::string visitor =
    //     input.GetExtension(hello_world::enclave_input_hello).to_greet();

    // LOG(INFO) << "Hello " << visitor;

    // if (output) {
    //   LOG(INFO) << "Incrementing visitor count...";
    //   output->MutableExtension(hello_world::enclave_output_hello)
    //       ->set_greeting_message(
    //           absl::StrCat("Hello ", visitor, "! You are visitor #",
    //                        ++visitor_count_, " to this enclave."));
    // }
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
