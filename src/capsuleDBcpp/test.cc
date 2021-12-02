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
    m->put("testkey", "testval");
    std::string requestedVal = m->get("testkey");
    std::cout << requestedVal;
}
