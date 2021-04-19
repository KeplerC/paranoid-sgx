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


#ifndef __COMMON_H
#define __COMMON_H

// Key for coordinator Request To Send(RTS)
#define COORDINATOR_RTS_KEY "PARANOID_RTS"
// Key for latest sync packet
#define COORDINATOR_SYNC_KEY "PARANOID_SYNC"
// Key for latest EOE
#define COORDINATOR_EOE_KEY "PARANOID_EOE"

#define TOTAL_THREADS 3

enum OCALL_ID {
    OCALL_PUT,
};

enum ECALL_ID {
    ECALL_PUT,
};

typedef struct {
    uint64_t* cyclesCount;
    uint64_t  counter;
    void*     data; 
    OCALL_ID  ocall_id; 
} OcallParams;

typedef struct {
    void*     data; 
    ECALL_ID  ecall_id; 
} EcallParams;


#endif
