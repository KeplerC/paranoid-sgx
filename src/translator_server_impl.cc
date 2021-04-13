/*
 *
 * Copyright 2019 Asylo authors
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

#include "src/translator_server_impl.h"

#include <iostream>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "include/grpcpp/grpcpp.h"

namespace examples {
namespace secure_grpc {

TranslatorServerImpl::TranslatorServerImpl(asylo::IdentityAclPredicate acl): 
      Service(),
      // Initialize the translation map with a few known translations.
      translation_map_({{"asylo", "sanctuary"},
                        {"istio", "sail"},
                        {"kubernetes", "helmsman"}}),
      acl_(std::move(acl)) {
        memset(key_pair_lst,0, MAX_WORKERS*sizeof(struct key_pair));
      }


  void generate_key_pair(struct key_pair *key_pair){
    key_pair->priv_key = 0x1010; 
    key_pair->pub_key = 0x1010; 
  }

  struct key_pair *TranslatorServerImpl::find_free_key_pair_idx(){

    //Lock list 
    for(int i = 0; i < MAX_WORKERS; i++){
      printf("i: %d\n", i);
      if(key_pair_lst[i].valid == KEY_PAIR_INVALID){
        //Unlock
        printf("Found free keypair\n");
        key_pair_lst[i].valid = KEY_PAIR_VALID; 
        return &key_pair_lst[i];
      }
    }

    //Unlock 
    return NULL;

  }

  ::grpc::Status TranslatorServerImpl::RetrieveKeyPair(
      ::grpc::ServerContext *context,
      const grpc_server::RetrieveKeyPairRequest *request,
      grpc_server::RetrieveKeyPairResponse *response){

    // First, access the authentication properties of the connection through
    // EnclaveAuthContext.
    auto auth_context_result = asylo::EnclaveAuthContext::CreateFromAuthContext(
        *context->auth_context());
    if (!auth_context_result.ok()) {
      LOG(ERROR) << "Failed to access authentication context: "
                << auth_context_result.status();
      return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                            "Failed to access authentication context");
    }


    asylo::EnclaveAuthContext auth_context = auth_context_result.ValueOrDie();

    // Now, check whether the peer is authorized to call this RPC.
    std::string explanation;
    auto authorized_result = auth_context.EvaluateAcl(acl_, &explanation);
    if (!authorized_result.ok()) {
      LOG(INFO) << authorized_result.status();
      return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                            "Error occurred while evaluating ACL");
    }

    if (!authorized_result.ValueOrDie()) {
    std::string combined_error =
        absl::StrCat("Peer is unauthorized for GetTranslation: ", explanation);
    std::cout << combined_error << std::endl;
    return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED,
                          combined_error);
    }
        
      LOG(INFO) << "[KVS Coordinator] Generating Key Pair";
      struct key_pair *key_pair = find_free_key_pair_idx();

      if(!key_pair){
        LOG(INFO) << "[KVS Coordinator] Could not find a free key pair!";
        return ::grpc::Status::OK;  
      }
      generate_key_pair(key_pair); 

      response->set_private_key("private key");
      response->set_public_key("public key");

      return ::grpc::Status::OK;        

    }

}  // namespace secure_grpc
}  // namespace examples
