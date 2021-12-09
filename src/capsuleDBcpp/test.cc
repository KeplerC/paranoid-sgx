#include <string>
#include <iostream>

#include "engine.hh"

int main()
{
    // Basic test
    CapsuleDB instance = spawnDB();

    kvs_payload kvsp_put = {};
    kvsp_put.key = "testkey";
    kvsp_put.value = "testval\n";
    instance.put(&kvsp_put);

    std::string requestedVal = instance.get("testkey");
    std::cout << requestedVal;
}
