 bazel run //src:faas_leader_sgx_hw --copt=-O3 -- \
   --acl="$(cat src/acl_ref_test.textproto)" \
   --server_max_lifetime=100000 \
   --port=3001