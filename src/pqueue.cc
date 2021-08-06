#include "pqueue.hpp"
#include "asylo/util/logging.h"
#include "common.h"

std::vector<kvs_payload> PQueue::dequeue(long unsigned int maxlen) {
    std::vector<kvs_payload> payload_l;
    sgx_spin_lock(&mq_spinlock);
    if (!msgqueue.empty()) {
        // prioritize special messages
        dequeue_msgqueue(&payload_l);
        sgx_spin_unlock(&mq_spinlock);
    } else {
        // no special messages, dequeue txns
        sgx_spin_unlock(&mq_spinlock);
        sgx_spin_lock(&tq_spinlock);
        dequeue_txnqueue(&payload_l, maxlen);
        sgx_spin_unlock(&tq_spinlock);
    }
    return payload_l;
}

bool PQueue::enqueue(const kvs_payload *payload) {
    if (payload->txn_msgType != DEFAULT_MSGTYPE) {
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

bool PQueue::enqueue_multi(const std::vector<kvs_payload> *payload_l) {
    if (((*payload_l)[0]).txn_msgType != DEFAULT_MSGTYPE) {
        // special message
        sgx_spin_lock(&mq_spinlock);
        msgqueue.insert(msgqueue.end(), payload_l->begin(), payload_l->end());
        sgx_spin_unlock(&mq_spinlock);
    } else {
        sgx_spin_lock(&tq_spinlock);
        txnqueue.insert(txnqueue.end(), payload_l->begin(), payload_l->end());
        sgx_spin_unlock(&tq_spinlock);
    }
    return true;
}

void PQueue::dequeue_txnqueue(std::vector<kvs_payload> *payload_l, long unsigned int maxlen){
    unsigned int len_to_get = std::min(txnqueue.size(), maxlen);
    if (!txnqueue.empty()){
        *payload_l = {txnqueue.begin(), txnqueue.begin()+len_to_get};
        txnqueue.erase(txnqueue.begin(), txnqueue.begin()+len_to_get);
    }
    return;
}

void PQueue::dequeue_msgqueue(std::vector<kvs_payload> *payload_l){
    if (!msgqueue.empty()){
        // return 1 special msg
        payload_l->push_back(msgqueue.front());
        msgqueue.pop_front();
    }
    return;
}
