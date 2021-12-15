#include <string>
#include <iostream>

#include "engine.hh"

int main()
{
    // Create instance with memtable/blocksize capacity of 2 key-value pairs
    CapsuleDB instance = spawnDB(50);
    instance.benchmark();
    std::string check_value = instance.get("6164213995759621");
    std::cout << "OUTPUT value=" << check_value << "\n\n";

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
    requestedVal = instance.get("testkey2");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Put testval3 at testkey, overriding testval
    kvsp_put.key = "testkey";
    kvsp_put.value = "testval3";
    kvsp_put.txn_timestamp = 3;
    instance.put(&kvsp_put);
    requestedVal = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Put testval4 at testkey4, causing memtable to write out to Level 0
    kvsp_put.key = "testkey4";
    kvsp_put.value = "testval4";
    kvsp_put.txn_timestamp = 4;
    instance.put(&kvsp_put);
    requestedVal = instance.get("testkey4");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Get value of testkey (should be testval3), shouldn't be in memtable, should have to check Level 0
    requestedVal = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Put testval5 at testkey5
    kvsp_put.key = "testkey5";
    kvsp_put.value = "testval5";
    kvsp_put.txn_timestamp = 5;
    instance.put(&kvsp_put);
    requestedVal = instance.get("testkey5");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // Put testval6 at testkey6, causing memtable to write out to Level 0. 
    kvsp_put.key = "testkey6";
    kvsp_put.value = "testval6";
    kvsp_put.txn_timestamp = 6;
    instance.put(&kvsp_put);
    requestedVal = instance.get("testkey6");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

    // There should be two blocks in Level 0 now.
    // Get value of testkey (should be testval3), shouldn't be in memtable, should have to check Level 0
    requestedVal = instance.get("testkey");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";
    // Get value of testkey2 (should be testval2), shouldn't be in memtable, should have to check Level 0
    requestedVal = instance.get("testkey2");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";
    // Get value of testkey4 (should be testval4), shouldn't be in memtable, should have to check Level 0
    requestedVal = instance.get("testkey4");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";
    // Get value of testkey5 (should be testval5), shouldn't be in memtable, should have to check Level 0
    requestedVal = instance.get("testkey5");
    std::cout << "OUTPUT value=" << requestedVal << "\n\n";

}
