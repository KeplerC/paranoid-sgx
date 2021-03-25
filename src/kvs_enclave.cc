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
#include "common.h"

class KVSApplication : public asylo::TrustedApplication {
 public:
  KVSApplication() : visitor_count_(0) {}

  /* 
    We can allocate OCALL params on stack because params are copied to circular buffer.
  */
  void put_ocall(data_capsule_t *dc){
      OcallParams args;
      args.ocall_id = OCALL_PUT;
      args.data = dc; 
      HotMsg_requestOCall( buffer, requestedCallID++, &args);
  }

  int HotMsg_requestOCall( HotMsg* hotMsg, int dataID, void *data ) {
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    int data_index = dataID % (MAX_QUEUE_LENGTH - 1);

    //Request call
    while( true ) {

        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
        sgx_spin_lock( &data_ptr->spinlock );

        if( data_ptr-> isRead == true ) {
            data_ptr-> isRead  = false;
            OcallParams *arg = (OcallParams *) data; 
            data_ptr->data = (void *) 1; 
            data_ptr->ocall_id = arg->ocall_id;      
            data_capsule_t *dc = (data_capsule_t *) arg->data; 

            //Must copy to the host since we cannot pass a pointer from enclave
            memcpy(&data_ptr->dc, dc, sizeof(data_capsule_t));
            sgx_spin_unlock( &data_ptr->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &data_ptr->spinlock );

        numRetries++;
        if( numRetries > MAX_RETRIES ){
            printf("exceeded tries\n");
            sgx_spin_unlock( &data_ptr->spinlock );
            return -1;
        }

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
          EcallParams *arg = (EcallParams *) data_ptr->data; 
          data_capsule_t *dc = (data_capsule_t *) arg->data; 

          switch(arg->ecall_id){
            case ECALL_PUT:
              printf("[ECALL] dc_id : %d\n", dc->id);
              put((data_capsule_t *) arg->data);
              break;
            default:
              printf("Invalid ECALL id: %d\n", arg->ecall_id);
          }

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
      HotMsg* hotmsg = (HotMsg*) input.GetExtension(hello_world::enclave_responder).responder();
      EnclaveMsgStartResponder( hotmsg );
      return asylo::Status::OkStatus();
    }

    buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
    requestedCallID = 0; 

    data_capsule_t dc[10];

    for( uint64_t i=0; i < 10; ++i ){
      dc[i].id = i; 
      put_ocall(&dc[i]);
    }

    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
  MemTable memtable;
  HotMsg *buffer;
  int requestedCallID; 

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
