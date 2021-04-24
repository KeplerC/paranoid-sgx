bazel run //src:hello_world_sgx_sim -- \
--server_address="localhost" \
--port=3001 \
--input_file=$(pwd)/src/input.js