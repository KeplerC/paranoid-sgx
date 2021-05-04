bazel run //src:hello_world_sgx_sim --copt=-O3 -- \
--input_file=$(pwd)/src/input.js