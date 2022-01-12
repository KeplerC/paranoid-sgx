#include <string>
#include <thread>
#include <vector>

#include "common.h"

#include "zmq_comm.hpp"
#include "capsuleDBcpp/cdb_network_client.hh"
#include "crypto.h"
#include "src/util/proto_util.hpp"
#include "benchmark.h"

const std::unique_ptr <asylo::SigningKey> signing_key = asylo::EcdsaP256Sha256SigningKey::Create().ValueOrDie();
zmq::socket_t* mcast_socket = new zmq::socket_t( context, ZMQ_PUSH);

// Generate valid CapsulePDU and sends serialized capsule to multicast port
std::string gen_string(const std::string &key, const std::string &value, bool isPut) {
    kvs_payload payload;
    // TODO: Formally define msgType
    asylo::KvToPayload(&payload, key, value, 0, isPut ? "PUT" : "GET");

    capsule_pdu dc;
    asylo::PayloadListToCapsule(&dc, &payload, 0);
    encrypt_payload_l(&dc);
    generate_hash(&dc);
    sign_dc(&dc, signing_key);

    std::string out_s;
    dc.SerializeToString(&out_s);

    mcast_socket->send(out_s);
}

std::string put(const std::string &key, const std::string &value) {
    return gen_string(key, value, true);
}

std::string get(const std::string &key) {
    return gen_string(key, nullptr, false);
}


// Spawn various network clients
void thread_run_zmq_server(unsigned thread_id){
    zmq_comm zs = zmq_comm(NET_SEED_SERVER_IP, thread_id, nullptr);
    zs.run_server();
}

void thread_run_zmq_client(unsigned thread_id, CapsuleDBNetworkClient* db){
    zmq_comm zs = zmq_comm(NET_CLIENT_IP, thread_id, db);
    zs.run_client();
}


/* 
 * Runs a simple test of CapsuleDB connected to ZMQ client, making use of the current multicast tree implementation.
 * Requests -> coordinator -> (multiple) workers
 */
int run_capsuleDB() {
    std::cout << "its running :D" << std::endl;
    std::vector <std::thread> worker_threads;
    int thread_id = START_CLIENT_ID;

    // Start central coordinator
    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));

    // Connect to multicast port
    mcast_socket->connect("tcp://*:" + std::to_string(NET_SERVER_MCAST_PORT));

    // Start worker instances, connects to coordinator
    CapsuleDBNetworkClient* instance = new CapsuleDBNetworkClient();
    worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, instance));

    // Start benchmark here
    // benchmark();
    put("test", "test");
    get("test");
    sleep(1 * 1000 * 1000);
    return 0; 
}

int main() {
    run_capsuleDB();
}