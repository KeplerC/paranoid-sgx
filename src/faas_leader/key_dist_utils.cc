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
#include "../attestation_util.h"

namespace examples {
namespace secure_grpc {

const uchar_vector SEED("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

KeyDistributionEnclave::KeyDistributionEnclave(asylo::IdentityAclPredicate acl): 
      Service(),
      acl_(std::move(acl)),
      hdSeed(SEED) {
        Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
      }

   ::grpc::Status KeyDistributionEnclave::RetrieveAssertionRequest(
            ::grpc::ServerContext *context,
            const grpc_server::RetrieveKeyPairRequest *request,
            grpc_server::AssertionRequestAsResponse *response){

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

  ::grpc::Status KeyDistributionEnclave::RetrieveKeyPair(
      ::grpc::ServerContext *context,
      const grpc_server::AssertionAsKeyRequest *request,
      grpc_server::RetrieveKeyPairResponse *response){
        
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

     ::grpc::Status KeyDistributionEnclave::KeyDistribution(
            ::grpc::ServerContext *context,
            const grpc_server::KeyDistributionRequest *request,
            grpc_server::KeyDistributionRequestResponse *response){

        asylo::AssertionRequest received_assertion_request;
        received_assertion_request.ParseFromString(request->assertion_request_for_key_dist());

        LOGI << "Generating assertion given the assertion request...";
        std::string age_server_address = "unix:/tmp/assertion_generator_enclave"; // Set this to the address of the AGE's gRPC server.
        asylo::SgxIdentity age_sgx_identity = asylo::GetSelfSgxIdentity(); // Set this to the AGE's expected identity.
        //initialize generator
        asylo::SgxAgeRemoteAssertionAuthorityConfig authority_config;
        authority_config.set_server_address(age_server_address);
        *authority_config.mutable_intel_root_certificate() = examples::secure_grpc::GetFakeIntelRoot();
        *authority_config.add_root_ca_certificates() = examples::secure_grpc::GetAdditionalRoot();
        std::unique_ptr<asylo::SgxAgeRemoteAssertionGenerator> generator_ = absl::make_unique<asylo::SgxAgeRemoteAssertionGenerator>();
        std::string config_in_str;
        authority_config.SerializeToString(&config_in_str);
        LOGI << config_in_str;
        generator_->Initialize(config_in_str);
        LOGI << "Generator is initialized: " << generator_ -> IsInitialized();

        asylo::Assertion assertion;
        generator_->Generate(examples::secure_grpc::kUserData, received_assertion_request, &assertion);
        std::string assertion_in_str;
        assertion.SerializeToString(&assertion_in_str);
        LOGI << "Returned assertion: " << assertion_in_str;

        return ::grpc::Status::OK;

    }

}  // namespace secure_grpc
}  // namespace examples
