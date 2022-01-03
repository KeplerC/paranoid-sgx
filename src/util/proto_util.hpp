#ifndef _PROTOUTIL_H
#define _PROTOUTIL_H

#include <string>
#include "src/kvs_include/capsule.h"
#include "src/proto/hello.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"

#define ASSIGN_OR_RETURN(lhs, rexpr)                \
do {                                                      \
  auto _asylo_status_or_value = (rexpr);                  \
  if (ABSL_PREDICT_FALSE(!_asylo_status_or_value.ok())) { \
    return -1;               \
  }                                                       \
  lhs = std::move(_asylo_status_or_value).ValueOrDie();   \
} while (false)

#define ASSIGN_OR_RETURN_FALSE(lhs, rexpr)                \
do {                                                      \
  auto _asylo_status_or_value = (rexpr);                  \
  if (ABSL_PREDICT_FALSE(!_asylo_status_or_value.ok())) { \
    return false;               \
  }                                                       \
  lhs = std::move(_asylo_status_or_value).ValueOrDie();   \
} while (false)

namespace asylo {

template <typename T>
bool generate_hash(capsule_pdu<T> *dc);

template <typename T>
bool sign_dc(capsule_pdu<T> *dc, const std::unique_ptr <SigningKey> &signing_key);

template <typename T>
bool verify_dc(const capsule_pdu<T> *dc, const std::unique_ptr <VerifyingKey> &verifying_key);

template <typename T>
bool encrypt_payload_l(capsule_pdu<T> *dc);

template <typename T>
bool decrypt_payload_l(capsule_pdu<T> *dc);

void KvToPayload(kvs_payload *payload, const std::string &key, const std::string &value, const int64_t timer,
                    const std::string &msgType);

template <typename T>
void PayloadListToCapsule(capsule_pdu<T> *dc, const std::vector<T> *payload_l, const int enclave_id);

template <typename T>
void CapsuleToProto(const capsule_pdu<T> *dc, hello_world::CapsulePDU *dcProto);

template <typename T>
void CapsuleFromProto(capsule_pdu<T> *dc, const hello_world::CapsulePDU *dcProto);

template <typename T>
void CapsuleToCapsule(capsule_pdu<T> *dc_new, const capsule_pdu<T> *dc);

template <typename T>
void dumpCapsule(const capsule_pdu<T> *dc);

void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto);

int64_t get_current_time();
} // namespace asylo

#endif 