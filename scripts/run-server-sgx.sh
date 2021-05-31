 bazel run //src:grpc_server_sgx_hw -- \
   --acl="$(cat src/acl_ref_test.textproto)" \
   --server_max_lifetime=100000 \
   --port=3001
