#include <vector>
#include "pqueue.hpp"
#include "asylo/util/logging.h"
#include "common.h"

kvs_payload PQueue::dequeue() {
    kvs_payload payload;
    sgx_spin_lock(&mq_spinlock);
    if (!msgqueue.empty()) {
        // prioritize special messages
        payload = dequeue_msgqueue();
        sgx_spin_unlock(&mq_spinlock);
    } else {
        // no special messages, dequeue txns
        sgx_spin_unlock(&mq_spinlock);
        sgx_spin_lock(&tq_spinlock);
        payload = dequeue_txnqueue();
        sgx_spin_unlock(&tq_spinlock);
    }
    return payload;
}

bool PQueue::enqueue(const kvs_payload *payload) {
    if (payload->txn_msgType != "") {
        // special message
        sgx_spin_lock(&mq_spinlock);
        msgqueue.push_back(*payload);
        sgx_spin_unlock(&mq_spinlock);
    } else {
        sgx_spin_lock(&tq_spinlock);
        txnqueue.push_back(*payload);
        sgx_spin_unlock(&tq_spinlock);
    }
    return true;
}

kvs_payload PQueue::dequeue_txnqueue(){
    kvs_payload payload;
    if (!txnqueue.empty()){
        payload = txnqueue.front();
        txnqueue.pop_front();
    }
    return payload;

    // TODO: change to return vector<kvs_payload>
    // std::vector<kvs_payload> payload_l;
    // while (!txnqueue.empty() && maxlen > 0) {
    //     payload_l.push_back(txnqueue.front());
    //     txnqueue.pop_front()
    //     maxlen -= 1;
    // }
    // return payload_l;
}

kvs_payload PQueue::dequeue_msgqueue(){
    kvs_payload payload;
    if (!msgqueue.empty()){
        payload = msgqueue.front();
        msgqueue.pop_front();
    }
    return payload;
}
