#!/bin/bash
JOBS=$1

mkdir -p coordinator_output
mkdir -p client_output

hosts="localhost"
time=600

if lsof -Pi :3001 -sTCP:LISTEN -t >/dev/null ; then
    echo "FAAS already running".
else
    bazel run //src:faas_leader_sgx_hw --copt=-O3 -- \
    --acl="$(cat src/acl_ref_test.textproto)" \
    --server_max_lifetime=100000 \
    --port=3001
fi

sleep 5

echo "Executing with 1 planner"
for i in $(seq 1 25); 
do 
    bazel run //src:mpl_listener_sgx_hw --copt=-O3 2> client_output/client_$i.txt & 
    sleep 3
    bazel run //src:mpl_coordinator_sgx_hw --copt=-O3 -- --hosts=$hosts --time_limit=$time 2> coordinator_output/coord_$i.txt
    sleep 1
done
