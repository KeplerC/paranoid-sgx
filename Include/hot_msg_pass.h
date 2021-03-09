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

typedef unsigned long int pthread_t;


typedef struct {
    pthread_t       responderThread;
    sgx_spinlock_t  spinlock;
    void*           data;
    uint16_t        callID;
    bool            keepPolling;
    bool            isRead;
    bool            busy;
} HotMsg;

typedef struct
{
    uint16_t numEntries;
    void (**callbacks)(void*);
} HotMsgTable;

#define HOTMSG_INITIALIZER  {0, SGX_SPINLOCK_INITIALIZER, NULL, 0, true, false, false }

static void HotMsg_init( HotMsg* hotMsg )
{
    hotMsg->responderThread    = 0;
    hotMsg->spinlock           = SGX_SPINLOCK_INITIALIZER;
    hotMsg->data               = NULL;
    hotMsg->callID             = 0;
    hotMsg->keepPolling        = true;
    hotMsg->isRead             = false;
    hotMsg->busy               = false;
}

//static inline void _mm_pause(void) __attribute__((always_inline));
//static inline void _mm_pause(void)
//{
//    __asm __volatile(
//        "pause"
//    );
//}


static inline int HotMsg_requestCall( HotMsg* hotMsg, uint16_t callID, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    //REquest call
    while( true ) {
        sgx_spin_lock( &hotMsg->spinlock );
        if( hotMsg->busy == false ) {
            hotMsg->busy        = true;
            hotMsg->isRead      = false;
            hotMsg->callID      = callID;
            hotMsg->data        = data;
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
    while( true )
    {
        sgx_spin_lock( &hotMsg->spinlock );
        if( hotMsg->isRead == true ){
            hotMsg->busy = false;
            sgx_spin_unlock( &hotMsg->spinlock );
            break;
        }

        sgx_spin_unlock( &hotMsg->spinlock );
        for( i = 0; i<3; ++i)
            _mm_pause();
    }

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
        //void *data = hotMsg->data;
        // sgx_spin_unlock( &hotMsg->spinlock );
        // data = (int*)hotCall->data;
        // printf( "Enclave: Data is at %p\n", data );
        // *data += 1;
        // sgx_spin_lock( &hotMsg->spinlock );
        hotMsg->isRead      = true;

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