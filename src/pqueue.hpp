#ifndef _PQUEUE_H
#define _PQUEUE_H

#include <deque>
#include <vector>
#include "capsule.h"
#include "sgx_spinlock.h"

class PQueue {
public:
    bool enqueue(const kvs_payload *payload);
    bool enqueue_multi(const std::vector<kvs_payload> *payload_l);
    std::vector<kvs_payload> dequeue(long unsigned int maxlen = 1);

    PQueue(){ tq_spinlock = 0; mq_spinlock = 0;}
private:
    void dequeue_txnqueue(std::vector<kvs_payload> *payload_l, long unsigned int maxlen);
    void dequeue_msgqueue(std::vector<kvs_payload> *payload_l);

    std::deque<kvs_payload> txnqueue; // queue for usual kv payloads
    std::deque<kvs_payload> msgqueue; // queue for special messages (e.g. EOE, RTS, SYNC)
    sgx_spinlock_t tq_spinlock;
    sgx_spinlock_t mq_spinlock;
};

#endif // _PQueue_H