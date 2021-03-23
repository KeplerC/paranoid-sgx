#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "double_linked_list.hpp"

#define MAX_MEM_SZ 300
#define BUCKET_NUM 5

struct bucket_entry{
  bool valid;
  DoublyLinkedList buckets; 
  absl::Mutex lock; 
};

class MemTable {
  public:
    size_t getSize(); 
    bool put(data_capsule_t *dc);
    data_capsule_t *get(data_capsule_id id);
    __uint32_t hash(data_capsule_id id);
    MemTable(){
      max_capacity = MAX_MEM_SZ; 
      curr_capacity = 0; 
    }
  private:
    bucket_entry memtable[MAX_MEM_SZ/BUCKET_NUM];
    size_t max_capacity;  
    size_t curr_capacity; 
};

#endif