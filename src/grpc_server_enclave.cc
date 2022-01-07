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

#include <chrono>
#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "src/grpc_server_config.pb.h"
#include "src/translator_server_impl.h"
#include "asylo/grpc/auth/enclave_server_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"
#include "asylo/grpc/auth/sgx_age_remote_credentials_options.h"
//#include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
//#include "asylo/identity/platform/sgx/sgx_identity.proto.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "common.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_generator.h"
#include "attestation_util.h"
namespace examples {
namespace secure_grpc {

// An enclave that runs a TranslatorServerImpl. We override the methods of
// TrustedApplication as follows:
//
// * Initialize starts the gRPC server.
// * Run retrieves the server port.
// * Finalize shuts down the server.
class GrpcServerEnclave final : public asylo::TrustedApplication {
 public:
  asylo::Status Initialize(const asylo::EnclaveConfig &enclave_config)
      LOCKS_EXCLUDED(server_mutex_) override;

  asylo::Status Run(const asylo::EnclaveInput &enclave_input,
                    asylo::EnclaveOutput *enclave_output) override;

  asylo::Status Finalize(const asylo::EnclaveFinal &enclave_final)
      LOCKS_EXCLUDED(server_mutex_) override;

 private:
  // Guards the |server_| member.
  absl::Mutex server_mutex_;

  // A gRPC server hosting |service_|.
  std::unique_ptr<::grpc::Server> server_ GUARDED_BY(server_mutex_);

  // The translation service.
  std::unique_ptr<TranslatorServerImpl> service_;

  // The server's selected port.
  int selected_port_;
};

asylo::Status GrpcServerEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config) LOCKS_EXCLUDED(server_mutex_) {
  // Fail if there is no server_address available.
  if (!enclave_config.HasExtension(grpc_server::server_address)) {
    return absl::InvalidArgumentError(
        "Expected a server_address extension on config.");
  }

  if (!enclave_config.HasExtension(grpc_server::port)) {
    return absl::InvalidArgumentError("Expected a port extension on config.");
  }

  if (!enclave_config.HasExtension(identity_expectation)) {
    return absl::InvalidArgumentError(
        "Expected an identity_expectation extension on config.");
  }

  // Lock |server_mutex_| so that we can start setting up the server.
  absl::MutexLock lock(&server_mutex_);

  // Check that the server is not already running.
  if (server_) {
    return absl::AlreadyExistsError("Server is already started");
  }

  // Create a ServerBuilder object to set up the server.
  ::grpc::ServerBuilder builder;

  // Use SGX local credentials to ensure that only local SGX enclaves can
  // connect to the server.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      asylo::EnclaveServerCredentials(
          asylo::BidirectionalSgxLocalCredentialsOptions());

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
  ASYLO_ASSIGN_OR_RETURN(assertion_request, MakeAssertionRequest({GetFakeIntelRoot()}));
  bool result;
  ASYLO_ASSIGN_OR_RETURN(result, generator_->CanGenerate(assertion_request));
  LOGI << "Generator can be generated: " << result;

  asylo::Assertion assertion;
  generator_->Generate(kUserData, assertion_request, &assertion);
  std::string assertion_in_str;
  assertion.SerializeToString(&assertion_in_str);
  LOGI << "Returned assertion: " << assertion_in_str;

  // Add a listening port to the server.
  builder.AddListeningPort(
      absl::StrCat(enclave_config.GetExtension(grpc_server::server_address),
                   ":", enclave_config.GetExtension(grpc_server::port)),
      server_credentials, &selected_port_);

  // Extract the SgxIdentityExpectation from the enclave's configuration. This
  // is used as the basis of the server's ACL.
  asylo::SgxIdentityExpectation sgx_expectation =
      enclave_config.GetExtension(identity_expectation);

  // Construct an ACL based from the SgxIdentityExpectation.
  asylo::IdentityAclPredicate acl;
  ASYLO_ASSIGN_OR_RETURN(
      *acl.mutable_expectation(),
      asylo::SerializeSgxIdentityExpectation(sgx_expectation));

  // Build the service with the configured ACL.
  service_ = absl::make_unique<TranslatorServerImpl>(std::move(acl));

  // Add the translator service to the server.
  builder.RegisterService(service_.get());

  // Start the server.
  server_ = builder.BuildAndStart();
  if (!server_) {
    return absl::InternalError("Failed to start server");
  }

  return asylo::Status::OkStatus();
}

asylo::Status GrpcServerEnclave::Run(const asylo::EnclaveInput &enclave_input,
                                     asylo::EnclaveOutput *enclave_output) {
  enclave_output->SetExtension(server_port, selected_port_);
  return asylo::Status::OkStatus();
}

asylo::Status GrpcServerEnclave::Finalize(
    const asylo::EnclaveFinal &enclave_final) LOCKS_EXCLUDED(server_mutex_) {
  // Lock |server_mutex_| so that we can start shutting down the server.
  absl::MutexLock lock(&server_mutex_);

  // If the server exists, then shut it down. Also delete the Server object to
  // indicate that it is no longer valid.
  if (server_) {
    LOG(INFO) << "Server shutting down";

    // Give all outstanding RPC calls 500 milliseconds to complete.
    server_->Shutdown(std::chrono::system_clock::now() +
                      std::chrono::milliseconds(500));
    server_.reset(nullptr);
  }

  return asylo::Status::OkStatus();
}

}  // namespace secure_grpc
}  // namespace examples

namespace asylo {

// Registers an instance of GrpcServerEnclave as the TrustedApplication. See
// trusted_application.h for more information.
TrustedApplication *BuildTrustedApplication() {
  return new examples::secure_grpc::GrpcServerEnclave;
}

}  // namespace asylo
