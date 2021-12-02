#include <string>
//#include "capsuledb.cc"
//#include "engine.cc"
#include <iostream>

#include "memtable_new.hpp"

extern int spawnDB();
int main()
{
    // Basic test
    spawnDB();
    Memtable *m;
    kvs_payload kvsp = new kvs_payload();
    kvsp->key = "testkey";
    kvsp->value = "testval";
    m->put(&kvs_payload);
    std::string requestedVal = m->get("testkey");
    std::cout << requestedVal;
}
