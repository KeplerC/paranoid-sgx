#include "cdb_test.hh"
#include "benchmark.h"

CapsuleDBTestClient client;

// Wrappers for benchmark
void benchmark_put(const std::string &key, const std::string &value) {
    client.put(key, value);
}

std::string benchmark_get(const std::string &key) {
    return client.get(key);
}


// Spawn root router
void thread_run_zmq_server(unsigned thread_id){
    zmq_comm zs = zmq_comm(NET_SEED_SERVER_IP, thread_id, nullptr, nullptr);
    zs.run_server();
}

// Spawn root router
void thread_run_zmq_client(unsigned thread_id){
    const absl::string_view signing_key_pem = {
                R"pem(-----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIF0Z0yrz9NNVFQU1754rHRJs+Qt04mr3vEgNok8uyU8QoAoGCCqGSM49
    AwEHoUQDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh2/XyY3ZdNrT8lq7FQ0Z6ENdm
    oG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
    -----END EC PRIVATE KEY-----)pem"
    };
    LOG(INFO) << "Creating new CapsuleDBNetworkClient instance\n";
    CapsuleDBNetworkClient* db = new CapsuleDBNetworkClient(50, 0, signing_key_pem);
    // CapsuleDBNetworkClient* db = new CapsuleDBNetworkClient(50, 0, client.signing_key_pem);
    LOG(INFO) << "Creating new CapsuleDBNetworkClient instance\n";
    zmq_comm zs = zmq_comm(NET_CLIENT_IP, thread_id, db, nullptr);
    zs.run_cdb_client();
}


/* 
 * Runs a simple test of CapsuleDB connected to ZMQ client, making use of the current multicast tree implementation.
 * Requests -> coordinator -> (multiple) workers
 */
int run_cdb_test_client() {
    // TODO: Add benchmark here
    // benchmark();
    // benchmark_put("testkey", "testvalue");
    while (true) {
        benchmark_put("3945957134849834", "TEST_VAL");
        sleep(3);
        LOG(INFO) << "Get result: " << benchmark_get("3945957134849834");
        sleep(5);
    }

    sleep(1 * 1000 * 1000);
    return 0; 
}

// IGNORE
int run_full_test() {
    std::vector <std::thread> worker_threads;

    // Start root router
    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));
    sleep(3);

    // Start CDB worker, connects to coordinator
    std::cout << "New client" << std::endl;
    worker_threads.push_back(std::thread(thread_run_zmq_client, 1));
    sleep(3);

    // TODO: Add benchmark here
    // benchmark();
    // benchmark_put("testkey", "testvalue");
    /*
    while (true) {
        benchmark_put("3945957134849834", "wef");
        sleep(5);
    }
    */

    // sleep(1 * 1000 * 1000);
    return 0; 
}


int main() {
    run_cdb_test_client();
}