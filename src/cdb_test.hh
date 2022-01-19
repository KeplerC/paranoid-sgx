#include <string>
#include <thread>
#include <vector>
#include <zmq.hpp>

#include "common.h"

#include "zmq_comm.hpp"
#include "capsuleDBcpp/cdb_network_client.hh"
#include "kvs_include/capsule.h"

class CapsuleDBTestClient {
    private:
        std::string recv_addr;

        zmq::context_t context_ = zmq::context_t(1);
        zmq::socket_t* mcast_socket = new zmq::socket_t(context_, ZMQ_PUSH);
        zmq::socket_t* recv_socket = new zmq::socket_t(context_, ZMQ_PULL);

        std::unique_ptr <asylo::SigningKey> signing_key;
        std::unique_ptr <asylo::VerifyingKey> verifying_key;

        asylo::Status setKeys() {
            // signing_key = asylo::EcdsaP256Sha256SigningKey::CreateFromPem(signing_key_pem);
            ASYLO_ASSIGN_OR_RETURN(this->signing_key, asylo::EcdsaP256Sha256SigningKey::CreateFromPem(signing_key_pem));
            ASYLO_ASSIGN_OR_RETURN(this->verifying_key, this->signing_key->GetVerifyingKey());
        }

        zmq::message_t gen_payload(const std::string &key, const std::string &value, bool isPut) {
            kvs_payload payload;
            std::vector<kvs_payload> payload_l;
            int64_t currTime = std::chrono::system_clock::to_time_t(
                                std::chrono::system_clock::now());

            // TODO: Formally define msgType
            if (isPut) {
                asylo::KvToPayload(&payload, key, value, currTime, "PUT");
            } else {
                asylo::KvToPayload(&payload, key, value, currTime, "GET");
            }
            payload_l.push_back(payload);

            // Create and encrypt DC
            capsule_pdu *dc = new capsule_pdu();
            asylo::PayloadListToCapsule(dc, &payload_l, 0);
            asylo::encrypt_payload_l(dc, true);
            asylo::generate_hash(dc);
            // The line below seg faults (:
            // asylo::sign_dc(dc, signing_key);

            // DUMP_CAPSULE(dc);

            // Convert DC -> CapsulePDU protobuf -> string -> zmq::message_t
            hello_world::CapsulePDU out_dc;
            asylo::CapsuleToProto(dc, &out_dc);

            std::string out_s;
            out_dc.SerializeToString(&out_s);

            zmq::message_t msg(out_s.size());
            memcpy(msg.data(), out_s.c_str(), out_s.size());

            return msg;
        }


    public:
        CapsuleDBTestClient() {
            // Connect to multicast socket
            std::string coordinator_ip = NET_SEED_ROUTER_IP;
            mcast_socket->connect ("tcp://" + coordinator_ip + ":6667");
            
            // Bind recv socket
            recv_addr = "tcp://*:" + std::to_string(NET_CDB_TEST_RESULT_PORT);
            LOG(INFO) << "Bind recv socket: " << recv_addr;
            recv_socket->bind (recv_addr);
            
            setKeys();

            LOG(INFO) << "Finish test client setup!";
        }
        void put(const std::string &key, const std::string &value) {
            zmq::message_t msg = gen_payload(key, value, true);
            mcast_socket->send(msg);
            LOG(INFO) << "Sent put msg!";
        }
        void get(const std::string &key) {
            zmq::message_t msg = gen_payload(key, "UNUSED_VAL", false);
            mcast_socket->send(msg);
            LOG(INFO) << "Sent get msg!";
        }

        const absl::string_view signing_key_pem = {
                        R"pem(-----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIF0Z0yrz9NNVFQU1754rHRJs+Qt04mr3vEgNok8uyU8QoAoGCCqGSM49
            AwEHoUQDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh2/XyY3ZdNrT8lq7FQ0Z6ENdm
            oG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
            -----END EC PRIVATE KEY-----)pem"
            };


};