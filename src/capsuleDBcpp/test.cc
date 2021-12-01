#include <string>
#include "capsuledb.cc";
#include "engine.cc";

int main() {
    // Basic test 
    spawnDB()
    put("testkey", "testval");
    std::string requestedVal = get("testkey");
    cout << requestedVal;
}