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

#include "src/faas_leader/key_dist_utils.h"

#include <iostream>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "include/grpcpp/grpcpp.h"
#include <hdkeys.h>
#include <Base58Check.h>

namespace examples {
namespace secure_grpc {

const uchar_vector SEED("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

KeyDistributionEnclave::KeyDistributionEnclave(asylo::IdentityAclPredicate acl): 
      Service(),
      acl_(std::move(acl)),
      hdSeed(SEED) {
        Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
      }

  ::grpc::Status KeyDistributionEnclave::RetrieveKeyPair(
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
        
      LOG(INFO) << "[KVS Coordinator] Generating Key Pair for " << request->identity();
      std::string identity = request->identity();

      if(client_state.find(identity) == client_state.end()) {
        // Initialize client state if not found
        client_state[identity] = {hdSeed.getMasterKey(), hdSeed.getMasterChainCode(), {}, {}, {}, {}, 0, 0 };

        client_state[identity].kde_prv = Coin::HDKeychain(client_state[identity].master_key, client_state[identity].master_chain_code);
        client_state[identity].kde_pub = client_state[identity].kde_prv.getPublic();

        client_state[identity].hardened_prv_child = client_state[identity].kde_prv.getChild(P(client_state[identity].hardened_child_index++));
        client_state[identity].hardened_pub_child = client_state[identity].hardened_prv_child.getPublic(); 
      }

      int faas_idx = client_state[identity].grand_child_index++;
      Coin::HDKeychain grand_child = client_state[identity].hardened_prv_child.getChild(faas_idx);

      std::string prv_key(grand_child.key().begin(), grand_child.key().end());

      std::vector<unsigned char> serialized_parent_key = client_state[identity].hardened_pub_child.extkey();
      std::string pub_key(serialized_parent_key.begin(), serialized_parent_key.end());

      response->set_child_private_key(prv_key);        
      response->set_parent_public_key(pub_key);
      response->set_faas_idx(faas_idx); 

      return ::grpc::Status::OK;        

    }

}  // namespace secure_grpc
}  // namespace examples
