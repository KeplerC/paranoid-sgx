//
// Created by keplerc on 1/6/22.
//
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

#ifndef PARANOID_SGX_ATTESTATION_UTIL_H
#define PARANOID_SGX_ATTESTATION_UTIL_H


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

    }
}

#endif //PARANOID_SGX_ATTESTATION_UTIL_H
