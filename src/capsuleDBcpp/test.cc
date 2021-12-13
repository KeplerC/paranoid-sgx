#include <string>
#include <iostream>

#include "engine.hh"

int main()
{
    // Create instance with memtable/blocksize capacity of 2 key-value pairs
    CapsuleDB instance = spawnDB(2);

    // Put testval at testkey
    kvs_payload kvsp_put = {};
    kvsp_put.key = "testkey";
    kvsp_put.value = "testval";
    kvsp_put.txn_timestamp = 1;
    instance.put(&kvsp_put);
    std::string requestedVal = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Put testval2 at testkey2
    kvsp_put.key = "testkey2";
    kvsp_put.value = "testval2";
    kvsp_put.txn_timestamp = 2;
    instance.put(&kvsp_put);
    std::string requestedVal2 = instance.get("testkey2");
    std::cout << "OUTPUT value=" << requestedVal2 << "\n\n";

    // Put testval3 at testkey, overriding testval
    kvsp_put.key = "testkey";
    kvsp_put.value = "testval3";
    kvsp_put.txn_timestamp = 3;
    instance.put(&kvsp_put);
    std::string requestedVal3 = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal3 << "\n\n";

    // Put testval4 at testkey4, causing memtable to write out to Level 0
    kvsp_put.key = "testkey4";
    kvsp_put.value = "testval4";
    kvsp_put.txn_timestamp = 4;
    instance.put(&kvsp_put);
    std::string requestedVal4 = instance.get("testkey4");
    std::cout << "OUTPUT value=" << requestedVal4 << "\n\n";

    // Get value of testkey (should be testval3), shouldn't be in memtable, should have to check Level 0
    std::string requestedVal5 = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal5 << "\n\n";
}
