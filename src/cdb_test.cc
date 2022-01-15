#include <string>
#include <thread>
#include <vector>
#include <zmq.hpp>

#include "common.h"

#include "zmq_comm.hpp"
#include "capsuleDBcpp/cdb_network_client.hh"
#include "kvs_include/capsule.h"
// #include "src/util/proto_util.hpp"

zmq::socket_t* mcast_socket;
char seed[] = "testSeed";
std::unique_ptr <asylo::SigningKey> signing_key;


// Generate valid CapsulePDU and sends serialized capsule to multicast port
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

void benchmark_put(const std::string &key, const std::string &value) {
    zmq::message_t msg = gen_payload(key, value, true);
    mcast_socket->send(msg);
    std::cout << "Sent put msg!" << std::endl;
}

void benchmark_get(const std::string &key) {
    // Temp workaround
    zmq::message_t msg = gen_payload(key, "UNUSED_VAL", false);
    mcast_socket->send(msg);
    std::cout << "Sent get msg!" << std::endl;
}

#include "benchmark.h"

// Spawn various network clients
void thread_run_zmq_server(unsigned thread_id){
    zmq_comm zs = zmq_comm(NET_SEED_SERVER_IP, thread_id, nullptr, nullptr);
    zs.run_server();
}

void thread_run_zmq_client(unsigned thread_id, CapsuleDBNetworkClient* db){
    zmq_comm zs = zmq_comm(NET_CLIENT_IP, thread_id, db, nullptr);
    zs.run_client();
}

asylo::Status setSignKey() {
    ASYLO_ASSIGN_OR_RETURN(signing_key, asylo::EcdsaP256Sha256SigningKey::CreateFromDer(seed));
}

/* 
 * Runs a simple test of CapsuleDB connected to ZMQ client, making use of the current multicast tree implementation.
 * Requests -> coordinator -> (multiple) workers
 */
int run_capsuleDB() {
    std::vector <std::thread> worker_threads;
    int thread_id = START_CLIENT_ID;
    setSignKey();

    // Start central coordinator
    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));
    sleep(3);

    // Connect to multicast port (hardcoded)
    // TODO: Use ports from common.h
    zmq::context_t context (1);
    mcast_socket = new zmq::socket_t(context, ZMQ_PUSH);
    mcast_socket -> connect ("tcp://LOCALHOST:6667");

    // Start worker instances, connects to coordinator
    std::cout << "New client" << std::endl;
    CapsuleDBNetworkClient* instance = new CapsuleDBNetworkClient(50, 0, seed);
    worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, instance));
    sleep(3);

    // TODO: Add benchmark here
    // Can run benchmark function generated from the YCSB traces!
    // benchmark();
    // benchmark_put("testkey", "testvalue");
	benchmark_get("3945957134849834");

    sleep(1 * 1000 * 1000);
    return 0; 
}

int main() {
    run_capsuleDB();
}