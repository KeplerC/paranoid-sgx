#include "gdp.h"
#include <cstdint>
#include "memtable.hpp"

// TODO: Replace hash function
__uint32_t MemTable:: hash(data_capsule_id id){
    return id % (MAX_MEM_SZ/BUCKET_NUM);
}


data_capsule_t *MemTable:: get(data_capsule_id id){

  uint32_t mem_idx = hash(id);

  memtable[mem_idx].lock.ReaderLock(); 
  if(!memtable[mem_idx].buckets.length()){
    printf("Index: %d is invalid!\n", mem_idx);
    return NULL;
  } 

  data_capsule_t *ret = memtable[mem_idx].buckets.search(id);
  memtable[mem_idx].lock.ReaderUnlock(); 


  if(!ret){
    //TODO: We must do an OCALL to fetch from the DataCapsule server 
  }
  return ret; 
}


/*
 Datacapsule is copied into memtable  
 We assume dc is provided by client enclave application 
*/
bool MemTable:: put(data_capsule_t *dc){
  
  uint32_t mem_idx = hash(dc->id);

  memtable[mem_idx].lock.WriterLock(); 
  if(memtable[mem_idx].buckets.length() >= BUCKET_NUM){
    memtable[mem_idx].buckets.delete_back();
    memtable[mem_idx].buckets.insert_front(dc);
  } else {
    memtable[mem_idx].buckets.insert_front(dc); 
    curr_capacity++; 
  }
  memtable[mem_idx].lock.WriterUnlock(); 

  //TODO: We must also do an OCALL to write 

  return true; 

}

size_t MemTable::getSize() {
  return curr_capacity; 
}