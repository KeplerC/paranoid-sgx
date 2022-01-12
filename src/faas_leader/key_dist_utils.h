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

#ifndef ASYLO_EXAMPLES_SECURE_GRPC_TRANSLATOR_SERVER_IMPL_H_
#define ASYLO_EXAMPLES_SECURE_GRPC_TRANSLATOR_SERVER_IMPL_H_

#include <string>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "src/translator_server.grpc.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server.h"

#include <hdkeys.h>


namespace examples {
namespace secure_grpc {

using grpc_server::Translator;

#define MAX_ACTIVE 16

enum key_state {KEY_PAIR_INVALID,  KEY_PAIR_VALID};


struct key_pair {
    bytes_t master_key;
    bytes_t master_chain_code;
    //Master keypair 
    Coin::HDKeychain kde_prv;
    Coin::HDKeychain kde_pub;
    //Hardened pub/priv keypairs 
    Coin::HDKeychain hardened_prv_child;
    Coin::HDKeychain hardened_pub_child;
    //Index for child/grandchild kids 
    uint64_t hardened_child_index; 
    uint64_t grand_child_index; 
};

class KeyDistributionEnclave final : public Translator::Service {
 public:
  // Configure the server with an ACL to enforce at the GetTranslation() RPC.
  explicit KeyDistributionEnclave(asylo::IdentityAclPredicate acl);

 private:

::grpc::Status RetrieveAssertionRequest(
        ::grpc::ServerContext *context,
        const grpc_server::RetrieveKeyPairRequest *request,
        grpc_server::AssertionRequestAsResponse *response) override;

  ::grpc::Status RetrieveKeyPair(
      ::grpc::ServerContext *context,
      const grpc_server::AssertionAsKeyRequest *request,
      grpc_server::RetrieveKeyPairResponse *response) override;

  ::grpc::Status KeyDistribution(
            ::grpc::ServerContext *context,
            const grpc_server::KeyDistributionRequest *request,
            grpc_server::KeyDistributionRequestResponse *response) override; 

  Coin::HDSeed hdSeed; 
  // An ACL that is enforced on the GetTranslation RPC.
  asylo::IdentityAclPredicate acl_;
  std::unordered_map<std::string, struct key_pair> client_state;

};

}  // namespace secure_grpc
}  // namespace examples

#endif  // ASYLO_EXAMPLES_SECURE_GRPC_TRANSLATOR_SERVER_IMPL_H_
