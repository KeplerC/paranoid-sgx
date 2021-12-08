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
#include "src/faas_leader/key_dist_utils.h"
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

namespace examples {
namespace secure_grpc {

    constexpr char kUserData[] = "User data";
    constexpr char kAttestationKeyCertificateDerHex[] =
            "0ab3030ab0034820f3376ae6b2f2034d3b7a4b48a778000000000000000000000000000000"
            "00000000000000000000000000000000000700000000000000e70000000000000049c80749"
            "3583e5fb0d8d7c80f21e7c89ccbbf2820e75f94b7ef0cd37623d46a4000000000000000000"
            "000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d"
            "774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000be7a8807a1ba8e"
            "785f17997bd29611637f7e8f12d4aec6c5696476f1c9ba52b8000000000000000000000000"
            "000000004153594c4f205349474e5245504f5254ff00ff00ff00ff00ff00ff00ff00ff0000"
            "000000000000000000000000000000cd49f8f05e1c228bf1d68d579549600e12dd010ac401"
            "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
            "bdb8ab220c1cb0089519cdf2818a91c6ccd957fcb0d528216139bf62e6a9272170e5b7a2e2"
            "faba7a8debad920c7c0a099e18ba4781cd389dec2489be981b20f11230417373657274696f"
            "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
            "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
            "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
            "12440a204f316d3250975af904ea23e1a8d86d4c4a034e69401650fc7e0324837036e00812"
            "20801b34199dc0a14397a0c830667677bd63f1ac0c3da73216ed4c4fe94df354ce";

    constexpr char kAttestationKeyCertificateIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "I\310\007I5\203\345\373\r\215|\200\362\036|\211\314\273\362\202\016u\371K~\360\3157b=F\244"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\203\327\031\347}\352\312\024p\366\272\366*MwC\003\310\231\333i\002\017\234p\356\035\374\010\307\316\236"
      }
      isvprodid: 0
      isvsvn: 0
    }
    miscselect: 0
    attributes { flags: 7 xfrm: 231 }
  }
  machine_configuration {
    cpu_svn { value: "A fake TCB level" }
    sgx_type: STANDARD
  }
)pb";

    constexpr char kAdditionalRootCertPem[] = R"pem(
-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgIUF/94/Naw8+Gb8bjA+ya6Zg9YHKswCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYDVQQD
DBFUZXN0IFJlYWwgUm9vdCBDQTAgFw0xOTA3MzAyMjU4MTFaGA8yMjkzMDUxNDIy
NTgxMVowcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNV
BAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRow
GAYDVQQDDBFUZXN0IFJlYWwgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABOrtpRA+iRlPQ7/g2ETz558ACVf8PJI3x+qN3NZ+Isdc11EZ6pqgL3bOysu/
Gy/mHGn8nuraH+KaVn1s60aOFr2jIzAhMBIGA1UdEwEB/wQIMAYBAf8CAQEwCwYD
VR0PBAQDAgIEMAoGCCqGSM49BAMCA0gAMEUCIA/rSJ6o/oIRuTk1MV0XjlZGF7+N
HQAOOAfPvg/KSecOAiEAx1o+05huNjGLOMl37Ee0Sy1elzyo12WgcVQVbTY47z4=
-----END CERTIFICATE-----
)pem";

// The key asserted by |kAttestationKeyCertificateDerHex|.
    constexpr char kAttestationSigningKeyPem[] = R"pem(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAFhNjtm+5QpSgIaAym1XzkMD6SzfJJRiYz2DNQI84G4oAoGCCqGSM49
AwEHoUQDQgAEvbirIgwcsAiVGc3ygYqRxszZV/yw1SghYTm/YuapJyFw5bei4vq6
eo3rrZIMfAoJnhi6R4HNOJ3sJIm+mBsg8Q==
-----END EC PRIVATE KEY-----
)pem";

// The expected peer identity.
    constexpr char kPeerIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\x9e\x34\x6c\x23\x51\x63\x79\x20\x9c\x7d\x5f\x00\x05\xbd\xa5\xb1\x95\x28\xda\xba\x7a\x6e\x84\x5e\x18\xf4\xf4\xc8\xc7\xb1\x88\x54"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\xed\x9a\xfc\x4f\xc9\xa4\x75\x50\x4a\x47\x43\x9f\xbe\x6c\x63\x0a\xba\x24\x1a\xa0\xef\xb5\x6c\xf6\xce\x68\x36\xf7\x6b\x24\x18\x94"
      }
      isvprodid: 55832
      isvsvn: 35707
    }
    miscselect: 1
    attributes { flags: 21 xfrm: 647 }
  }
  machine_configuration {
    cpu_svn { value: "A fake TCB level" }
    sgx_type: STANDARD
  }
)pb";

    asylo::Certificate GetFakeIntelRoot() {
        asylo::Certificate fake_intel_root;
        fake_intel_root.set_format(asylo::Certificate::X509_PEM);
        fake_intel_root.set_data(asylo::sgx::kFakeSgxRootCa.certificate_pem.data(),
                                 asylo::sgx::kFakeSgxRootCa.certificate_pem.size());
        return fake_intel_root;
    }

    asylo::Certificate GetAdditionalRoot() {
        asylo::Certificate additional_root;
        additional_root.set_format(asylo::Certificate::X509_PEM);
        additional_root.set_data(kAdditionalRootCertPem);
        return additional_root;
    }

    asylo::StatusOr<asylo::SgxAgeRemoteAssertionAuthorityConfig> CreateValidConfig(
            bool include_additional_root = true) {
        asylo::SgxAgeRemoteAssertionAuthorityConfig config;

        *config.mutable_intel_root_certificate() = GetFakeIntelRoot();

        asylo::SgxIdentity age_identity =
                asylo::ParseTextProtoOrDie(kAttestationKeyCertificateIdentity);

        asylo::SgxIdentityExpectation age_sgx_expectation;
        ASYLO_ASSIGN_OR_RETURN(
                age_sgx_expectation,
                asylo::CreateSgxIdentityExpectation(age_identity,
                                                    asylo::SgxIdentityMatchSpecOptions::DEFAULT));

        ASYLO_ASSIGN_OR_RETURN(
                *config.mutable_age_identity_expectation()->mutable_expectation(),
                asylo::SerializeSgxIdentityExpectation(age_sgx_expectation));

        if (include_additional_root) {
            *config.add_root_ca_certificates() = GetAdditionalRoot();
        }

        return config;
    }

    asylo::AssertionOffer CreateValidOffer() {
        asylo::sgx::RemoteAssertionOfferAdditionalInfo additional_info;
        *additional_info.add_root_ca_certificates() = GetFakeIntelRoot();
        *additional_info.add_root_ca_certificates() = GetAdditionalRoot();
        asylo::AssertionOffer offer;
        SetSgxAgeRemoteAssertionDescription(offer.mutable_description());
        offer.set_additional_information(additional_info.SerializeAsString());
        return offer;
    }

    asylo::StatusOr<asylo::Assertion> CreateValidAssertion() {
        asylo::sgx::RemoteAssertion remote_assertion;

        asylo::SgxIdentity peer_identity = asylo::ParseTextProtoOrDie(kPeerIdentity);

        std::unique_ptr<asylo::SigningKey> attestation_key;
        ASYLO_ASSIGN_OR_RETURN(
                attestation_key,
                asylo::EcdsaP256Sha256SigningKey::CreateFromPem(kAttestationSigningKeyPem));

        asylo::CertificateChain sgx_certificate_chain;
        asylo::Certificate *ak_cert = sgx_certificate_chain.add_certificates();
        ak_cert->set_format(asylo::Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
        ak_cert->set_data(absl::HexStringToBytes(kAttestationKeyCertificateDerHex));
        asylo::sgx::AppendFakePckCertificateChain(&sgx_certificate_chain);

        ASYLO_RETURN_IF_ERROR(
                asylo::sgx::MakeRemoteAssertion(kUserData, peer_identity, *attestation_key,
                                         {sgx_certificate_chain}, &remote_assertion));

        asylo::Assertion assertion;
        asylo::SetSgxAgeRemoteAssertionDescription(assertion.mutable_description());
        if (!remote_assertion.SerializeToString(assertion.mutable_assertion())) {
            return asylo::Status(absl::StatusCode::kInternal,
                          "Could not serialize remote assertion to string");
        }
        return assertion;
    }

    // Creates an assertion request for the SGX AGE remote assertion generator.
    asylo::StatusOr<asylo::AssertionRequest> MakeAssertionRequest(
            absl::Span<const asylo::Certificate> certificates) {
        asylo::AssertionRequest assertion_request;
        asylo::SetSgxAgeRemoteAssertionDescription(
                assertion_request.mutable_description());

        asylo::sgx::RemoteAssertionRequestAdditionalInfo additional_info;
        for (const auto &certificate : certificates) {
            *additional_info.add_root_ca_certificates() = certificate;
        }

        if (!additional_info.SerializeToString(
                assertion_request.mutable_additional_information())) {
            return asylo::Status(
                    absl::StatusCode::kInvalidArgument,
                    "Failed to serialize additional_info for remote assertion request");
        }

        return assertion_request;
    }


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
  std::unique_ptr<KeyDistributionEnclave> service_;

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

//  LOGI << "1";
//  asylo::EnclaveConfig config;
//  ASYLO_ASSIGN_OR_RETURN(*(config.add_enclave_assertion_authority_configs()),
//  asylo::CreateSgxAgeRemoteAssertionAuthorityConfig(age_server_address, age_sgx_identity));
//  LOGI << "2";

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
  service_ = absl::make_unique<KeyDistributionEnclave>(std::move(acl));

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
