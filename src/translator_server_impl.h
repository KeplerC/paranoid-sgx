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

namespace examples {
namespace secure_grpc {

using grpc_server::Translator;

#define MAX_WORKERS 16

enum key_state {KEY_PAIR_INVALID,  KEY_PAIR_VALID};


struct key_pair {
    key_state valid; 
    __uint64_t priv_key;
    __int64_t pub_key; 
};

class TranslatorServerImpl final : public Translator::Service {
 public:
  // Configure the server with an ACL to enforce at the GetTranslation() RPC.
  explicit TranslatorServerImpl(asylo::IdentityAclPredicate acl);

 private:
  ::grpc::Status RetrieveKeyPair(
      ::grpc::ServerContext *context,
      const grpc_server::RetrieveKeyPairRequest *request,
      grpc_server::RetrieveKeyPairResponse *response) override;

  // A map from words to their translations.
  absl::flat_hash_map<std::string, std::string> translation_map_;

  // An ACL that is enforced on the GetTranslation RPC.
  asylo::IdentityAclPredicate acl_;

  struct key_pair key_pair_lst[MAX_WORKERS];
  struct key_pair *find_free_key_pair_idx();

};

}  // namespace secure_grpc
}  // namespace examples

#endif  // ASYLO_EXAMPLES_SECURE_GRPC_TRANSLATOR_SERVER_IMPL_H_
