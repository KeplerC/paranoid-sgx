#include "gdp.h"
#include <cstdint>
#include "memtable.hpp"

// TODO: Replace hash function
__uint32_t MemTable:: hash(data_capsule_id id){
    return id % (MAX_MEM_SZ/BUCKET_NUM);
}


data_capsule_t *MemTable:: get(data_capsule_id id){

  uint32_t mem_idx = hash(id);

  if(!memtable[mem_idx].buckets.length()){
    printf("Index: %d is invalid!\n", mem_idx);
    return NULL;
  }

  data_capsule_t *ret = memtable[mem_idx].buckets.search(id);
  return ret; 
}


/*
 Datacapsule is copied into memtable  
 We assume dc is provided by client enclave application 
*/
bool MemTable:: put(data_capsule_t *dc){
  
  uint32_t mem_idx = hash(dc->id);

  if(memtable[mem_idx].buckets.length() >= BUCKET_NUM){
    memtable[mem_idx].buckets.delete_back();
    memtable[mem_idx].buckets.insert_front(dc);
  } else {
    memtable[mem_idx].buckets.insert_front(dc); 
    curr_capacity++; 
  }

  return true; 

}

size_t MemTable::getSize() {
  return curr_capacity; 
}