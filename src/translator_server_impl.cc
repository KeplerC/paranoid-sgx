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
#include "attestation_util.h"

namespace examples {
namespace secure_grpc {

TranslatorServerImpl::TranslatorServerImpl(asylo::IdentityAclPredicate acl): 
      Service(),
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
      if(key_pair_lst[i].valid == KEY_PAIR_INVALID){
        //Unlock
        key_pair_lst[i].valid = KEY_PAIR_VALID; 
        return &key_pair_lst[i];
      }
    }

    //Unlock 
    return NULL;

  }
    ::grpc::Status TranslatorServerImpl::RetrieveAssertionRequest(
            ::grpc::ServerContext *context,
            const grpc_server::RetrieveKeyPairRequest *request,
            grpc_server::AssertionRequest *response){

        std::string age_server_address = "unix:/tmp/assertion_generator_enclave"; // Set this to the address of the AGE's gRPC server.
        asylo::SgxIdentity age_sgx_identity = asylo::GetSelfSgxIdentity(); // Set this to the AGE's expected identity.

        //initialize generator
        asylo::SgxAgeRemoteAssertionAuthorityConfig authority_config;
        authority_config.set_server_address(age_server_address);
        *authority_config.mutable_intel_root_certificate() = GetFakeIntelRoot();
        *authority_config.add_root_ca_certificates() = GetAdditionalRoot();
        std::unique_ptr<asylo::SgxAgeRemoteAssertionGenerator> generator_ = absl::make_unique<asylo::SgxAgeRemoteAssertionGenerator>();
        std::string config_in_str;
        authority_config.SerializeToString(&config_in_str);
        LOGI << config_in_str;
        generator_->Initialize(config_in_str);
        LOGI << "Generator is initialized: " << generator_ -> IsInitialized();

        //make assertion request
        asylo::AssertionRequest assertion_request;
        //ASYLO_ASSIGN_OR_RETURN(assertion_request, MakeAssertionRequest({GetFakeIntelRoot()}));
        assertion_request = std::move(MakeAssertionRequest({GetFakeIntelRoot()})).value();

        std::string assertion_req_in_str;
        assertion_request.SerializeToString(&assertion_req_in_str);
        response -> set_assertion_request(assertion_req_in_str);
        return ::grpc::Status::OK;

    }
  ::grpc::Status TranslatorServerImpl::RetrieveKeyPair(
          ::grpc::ServerContext *context,
          const grpc_server::Assertion *request,
          grpc_server::RetrieveKeyPairResponse *response){

      LOG(INFO) << "[KVS Coordinator] Generating Key Pair";
      struct key_pair *key_pair = find_free_key_pair_idx();

      if(!key_pair){
        LOG(INFO) << "[KVS Coordinator] Could not find a free key pair!";
        return ::grpc::Status::OK;
      }
      generate_key_pair(key_pair);

      response->set_private_key("priv kkkkkkey");
      response->set_public_key("pub kkkkkkey");

      return ::grpc::Status::OK;

    }


//  ::grpc::Status TranslatorServerImpl::RetrieveKeyPair(
//      ::grpc::ServerContext *context,
//      const grpc_server::RetrieveKeyPairRequest *request,
//      grpc_server::RetrieveKeyPairResponse *response){
//
//    // First, access the authentication properties of the connection through
//    // EnclaveAuthContext.
//    auto auth_context_result = asylo::EnclaveAuthContext::CreateFromAuthContext(
//        *context->auth_context());
//    if (!auth_context_result.ok()) {
//      LOG(ERROR) << "Failed to access authentication context: "
//                << auth_context_result.status();
//      return ::grpc::Status(::grpc::StatusCode::INTERNAL,
//                            "Failed to access authentication context");
//    }
//
//
//    asylo::EnclaveAuthContext auth_context = auth_context_result.ValueOrDie();
//
//    // Now, check whether the peer is authorized to call this RPC.
//    std::string explanation;
//    auto authorized_result = auth_context.EvaluateAcl(acl_, &explanation);
//    if (!authorized_result.ok()) {
//      LOG(INFO) << authorized_result.status();
//      return ::grpc::Status(::grpc::StatusCode::INTERNAL,
//                            "Error occurred while evaluating ACL");
//    }
//
//    if (!authorized_result.ValueOrDie()) {
//    std::string combined_error =
//        absl::StrCat("Peer is unauthorized for GetTranslation: ", explanation);
//    std::cout << combined_error << std::endl;
//    return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED,
//                          combined_error);
//    }
//
//      LOG(INFO) << "[KVS Coordinator] Generating Key Pair";
//      struct key_pair *key_pair = find_free_key_pair_idx();
//
//      if(!key_pair){
//        LOG(INFO) << "[KVS Coordinator] Could not find a free key pair!";
//        return ::grpc::Status::OK;
//      }
//      generate_key_pair(key_pair);
//
//      response->set_private_key("priv kkkkkkey");
//      response->set_public_key("pub kkkkkkey");
//
//      return ::grpc::Status::OK;
//
//    }

}  // namespace secure_grpc
}  // namespace examples
