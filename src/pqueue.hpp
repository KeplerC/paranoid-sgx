#ifndef _PQUEUE_H
#define _PQUEUE_H

#include <deque>
#include "capsule.h"
#include "sgx_spinlock.h"

class PQueue {
public:
    bool enqueue(const kvs_payload *payload);
    kvs_payload dequeue();

    PQueue(){ tq_spinlock = 0; mq_spinlock = 0;}
private:
    kvs_payload dequeue_txnqueue();
    kvs_payload dequeue_msgqueue();

    std::deque<kvs_payload> txnqueue; // queue for usual kv payloads
    std::deque<kvs_payload> msgqueue; // queue for special messages (e.g. EOE, RTS, SYNC)
    sgx_spinlock_t tq_spinlock;
    sgx_spinlock_t mq_spinlock;
};

#endif // _PQueue_H