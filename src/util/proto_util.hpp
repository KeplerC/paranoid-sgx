#ifndef _PROTOUTIL_H
#define _PROTOUTIL_H

#include <string>
#include "src/kvs_include/capsule.h"
#include "src/proto/hello.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include <secp256k1.h>

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

bool generate_hash(capsule_pdu *dc);

bool sign_dc(capsule_pdu *dc, const secp256k1_key& key, int32_t faas_idx);

bool verify_dc_hd_wallet(std::unordered_map<int, secp256k1_key> enclave_worker_keys, const capsule_pdu *dc, const Coin::HDKeychain& key);

bool verify_dc(std::unordered_map<int, secp256k1_key> enclave_worker_keys, const capsule_pdu *dc, const Coin::HDKeychain& key);

bool encrypt_payload_l(capsule_pdu *dc, bool encryption_need);

bool decrypt_payload_l(capsule_pdu *dc);

void KvToPayload(kvs_payload *payload, const std::string &key, const std::string &value, const int64_t timer,
                    const std::string &msgType);

void PayloadListToCapsule(capsule_pdu *dc, const std::vector<kvs_payload> *payload_l, const int enclave_id);

void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto);

void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto);

void CapsuleToCapsule(capsule_pdu *dc_new, const capsule_pdu *dc);

void dumpCapsule(const capsule_pdu *dc);

void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto);

int64_t get_current_time();
} // namespace asylo

#endif 