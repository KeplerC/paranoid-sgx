#include <string>
//#include "capsuledb.cc"
//#include "engine.cc"

#include "../kvs_include/capsule.h"
#include "memtable_new.hpp"

extern int spawnDB();
int main()
{
    // Basic test
    spawnDB();
    Memtable *m;
    m->put("testkey", "testval");
    std::string requestedVal = m->get("testkey");
    cout << requestedVal;
}
