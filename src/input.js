print("[ENCLAVE] ===CLIENT PUT=== ");
print("[ENCLAVE] Generating a new capsule PDU ");
put("default_key", "default_value_longggggggggggggggggggggggg");payload = get("default_key");

print("[ENCLAVE] ===CLIENT GET=== ");
payload = get("default_key");
print("DataCapsule payload.key is " + payload.key);
print("DataCapsule payload.value is " + payload.val);

var x, y, z;  // Declare 3 variables
x = 5;    // Assign the value 5 to x
y = 6;    // Assign the value 6 to y
z = x + y;  // Assign the sum of x and y to z
psl_return(z.toString());
