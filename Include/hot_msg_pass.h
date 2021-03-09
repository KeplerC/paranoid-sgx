// ----------------------------------------
// HotCalls
// Copyright 2017 The Regents of the University of Michigan
// Ofir Weisse, Valeria Bertacco and Todd Austin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------

//Author: Ofir Weisse, www.OfirWeisse.com, email: oweisse (at) umich (dot) edu
//Based on ISCA 2017 "HotCalls" paper. 
//Link to the paper can be found at http://www.ofirweisse.com/previous_work.html
//If you make nay use of this code for academic purpose, please cite the paper. 



#ifndef __FAST_SGX_MSG_PASS_H
#define __FAST_SGX_MSG_PASS_H



// #include <stdlib.h>
#include <sgx_spinlock.h>
#include <stdbool.h>
#include "hot_msg_pass.h"

// #include "utils.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#define MAX_QUEUE_LENGTH 100

typedef unsigned long int pthread_t;




typedef struct {
    pthread_t       responderThread;
    sgx_spinlock_t  spinlock;
    bool            keepPolling;
    bool            busy;
    void**    MsgQueue;
    int front, rear, size;
    unsigned capacity;
} HotMsg;


#define HOTMSG_INITIALIZER  {0, SGX_SPINLOCK_INITIALIZER, true, false, nullptr, 0, 0, 0, 0}
static void HotMsg_init( HotMsg* hotMsg )
{
    hotMsg->responderThread    = 0;
    hotMsg->spinlock           = SGX_SPINLOCK_INITIALIZER;
    hotMsg->keepPolling        = true;
    hotMsg->busy             = false;
    hotMsg->front = hotMsg->size = 0;
    hotMsg->capacity = MAX_QUEUE_LENGTH;
    hotMsg->rear = MAX_QUEUE_LENGTH - 1;
    hotMsg->MsgQueue = (void**)malloc(hotMsg->capacity * sizeof(void*));
}


static void HotMsg_enqueue( HotMsg* queue, void* data)
{
    if ( (queue->size == queue->capacity))
        return;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    queue->MsgQueue[queue->rear] = data;
    queue->size = queue->size + 1;
}

static void*  HotMsg_dequeue(HotMsg* queue)
{
    if ((queue->size == 0))
        return 0;
    void* item = queue->MsgQueue[queue->front];
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}


//static inline void _mm_pause(void) __attribute__((always_inline));
//static inline void _mm_pause(void)
//{
//    __asm __volatile(
//        "pause"
//    );
//}


static inline int HotMsg_requestCall( HotMsg* hotMsg, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    //Request call
    while( true ) {
        sgx_spin_lock( &hotMsg->spinlock );
        if( hotMsg->busy == false ) {
            hotMsg->busy        = true;
            HotMsg_enqueue(hotMsg, data);
            sgx_spin_unlock( &hotMsg->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &hotMsg->spinlock );

        numRetries++;
        if( numRetries > MAX_RETRIES )
            return -1;

        for( i = 0; i<3; ++i)
            _mm_pause();
    }

    //wait for answer
//    while( true )
//    {
//        sgx_spin_lock( &hotMsg->spinlock );
//        if( hotMsg->MsgQueue->isRead == true ){
//            hotMsg->busy = false;
//            sgx_spin_unlock( &hotMsg->spinlock );
//            break;
//        }
//
//        sgx_spin_unlock( &hotMsg->spinlock );
//        for( i = 0; i<3; ++i)
//            _mm_pause();
//    }

    return numRetries;
}

static inline void HotMsg_waitForCall( HotMsg *hotMsg )  __attribute__((always_inline));
static inline void HotMsg_waitForCall( HotMsg *hotMsg )
{
    static int i;
    // volatile void *data;
    while( true )
    {
        sgx_spin_lock( &hotMsg->spinlock );
        if( hotMsg->keepPolling != true ) {
            sgx_spin_unlock( &hotMsg->spinlock );
            break;
        }

        //volatile uint16_t callID = hotMsg->callID;
        void *data = (void*) HotMsg_dequeue(hotMsg);
        //sgx_spin_unlock( &hotMsg->spinlock );
        // data = (int*)hotCall->data;
        // printf( "Enclave: Data is at %p\n", data );
        // *data += 1;
        // sgx_spin_lock( &hotMsg->spinlock );

        sgx_spin_unlock( &hotMsg->spinlock );
        for( i = 0; i<3; ++i)
            _mm_pause();

        // _mm_pause();
        //     _mm_pause();
        // _mm_pause();
    }

}
static inline void StopMsgResponder( HotMsg *hotMsg );
static inline void StopMsgResponder( HotMsg *hotMsg )
{
    sgx_spin_lock( &hotMsg->spinlock );
    hotMsg->keepPolling = false;
    sgx_spin_unlock( &hotMsg->spinlock );
}


#endif