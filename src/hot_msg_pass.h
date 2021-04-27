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


#include <stdbool.h>
#include "common.h"
#include "sgx_spinlock.h"
#include "capsule.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#define MAX_QUEUE_LENGTH 1000

typedef unsigned long int pthread_t;

typedef struct {
    sgx_spinlock_t  spinlock;
    bool            isRead;
    void*           data;
    int             size; 
    int             ocall_id;
} HotData;


typedef struct {
    sgx_spinlock_t  spinlock;
    pthread_t       responderThread;
    bool            initialized; 
    bool            keepPolling;
    HotData**    MsgQueue;
} HotMsg;


#define HOTMSG_INITIALIZER  {0, true, nullptr}
#define HOTDATA_INITIALIZER  {SGX_SPINLOCK_INITIALIZER, 0, 0}
static void HotMsg_init( HotMsg* hotMsg )
{
    hotMsg->responderThread    = 0;
    hotMsg->keepPolling        = true;
    hotMsg->MsgQueue = (HotData**) calloc(MAX_QUEUE_LENGTH, sizeof(HotData*));
    for(int i = 0; i < MAX_QUEUE_LENGTH; i++){
        HotData* hd = (HotData*) calloc(1, sizeof(HotData));
        hd->isRead = true; 
        (hotMsg->MsgQueue)[i] = hd;
    }
}

static inline void _mm_sleep(void) __attribute__((always_inline));
static inline void _mm_sleep(void)
{
    __asm __volatile(
        "pause"
    );
}


static inline int HotMsg_requestECall( HotMsg* hotMsg, int dataID, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    int data_index = dataID % (MAX_QUEUE_LENGTH - 1);
    //Request call
    while( true ) {

        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
        sgx_spin_lock( &data_ptr->spinlock );
        // printf("[HotMsg_requestCall] keep polling: %d\n", hotMsg->keepPolling);

        if( data_ptr-> isRead == true ) {
            data_ptr-> isRead  = false;
            data_ptr->data = data;
            sgx_spin_unlock( &data_ptr->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &data_ptr->spinlock );

        numRetries++;
        if( numRetries > MAX_RETRIES ){
            printf("exceeded tries");
            sgx_spin_unlock( &data_ptr->spinlock );
            return -1;
        }

        for( i = 0; i<3; ++i)
            _mm_sleep();
    }

    return numRetries;
}

static inline void HotMsg_waitForCall( HotMsg *hotMsg )  __attribute__((always_inline));
// static inline void HotMsg_waitForCall( HotMsg *hotMsg )
// {
//     int dataID = 0;

//     static int i;
//     // printf("[HotMsg_waitForCall] data_ID: %d\n", dataID);

//     while( true )
//     {
//         // printf("[HotMsg_waitForCall] data_ptr: %p, data_id: %d\n", hotMsg -> MsgQueue[dataID], dataID);
//         HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
//         if (data_ptr == 0){
//             continue;
//         }
//         if( hotMsg->keepPolling != true ) {
//             break;
//         }

//         sgx_spin_lock( &data_ptr->spinlock );
//         //do stuff

//         if(data_ptr->data){
//             //Message exists!
//             data_capsule_t *arg = (data_capsule_t *) data_ptr->data; 
//             printf("[HotMsg_waitForCall] FOUND MESSSAGE: dc_id: %d\n");
//             data_ptr->data = 0; 
//         }

//         // printf("[HotMsg_waitForCall] data_ptr->isRead: %d, dataID: %d\n", data_ptr->isRead, dataID);

//         data_ptr->isRead      = true;
//         sgx_spin_unlock( &data_ptr->spinlock );
//         dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
//         for( i = 0; i<3; ++i)
//             _mm_pause();
//     }
// }

// This function is here for purely measurement purpose
// enclave does not support rdtsp, and our msg passing does not call functions
// we need to update the latency somewhere, and to be fair with hotcall,
// I wrote something similar to hotcall
static inline void HotMsg_waitForCall_Measurement( HotMsg *hotMsg, uint64_t (*rdtsp_ptr)() )  __attribute__((always_inline));
static inline void HotMsg_waitForCall_Measurement( HotMsg *hotMsg, uint64_t (*rdtsp_ptr)() )
{
    int dataID = 0;

    static uint64_t startTime     = 0;
    static int i;
    // volatile void *data;
    while( true )
    {
        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
        if (data_ptr == 0){
            continue;
        }
        if( hotMsg->keepPolling != true ) {
            break;
        }

        // data_ptr->lock.Lock(); 
        sgx_spin_lock( &data_ptr->spinlock );

        OcallParams* ocallParams = (OcallParams*)data_ptr->data;
        data_ptr->isRead      = true;
        // data_ptr->lock.Unlock(); 
        sgx_spin_unlock( &data_ptr->spinlock );

        *(ocallParams->cyclesCount)  = rdtsp_ptr() - startTime;
        startTime     = rdtsp_ptr();

        dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
        for( i = 0; i<3; ++i)
            _mm_pause();
    }
}

static inline void StopMsgResponder( HotMsg *hotMsg );
static inline void StopMsgResponder( HotMsg *hotMsg )
{
    hotMsg->keepPolling = false;
}


#endif