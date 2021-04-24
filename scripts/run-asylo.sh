bazel run //src:hello_world_sgx_sim -- \
--payload=$(whoami) \
--server_address="localhost" \
--port=3001 \
--input_file=$(pwd)/src/input.js