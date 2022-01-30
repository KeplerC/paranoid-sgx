AGE_PATH=/home/gdpmobile5/paranoid-sgx/bazel-bin/external/com_google_asylo/asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_sgx_sim.so.runfiles/com_google_asylo/asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_sgx_sim.so
# bazel build --define="SGX_SIM=1"  @com_google_asylo//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_sgx_sim.so
bazel run @com_google_asylo//asylo/identity/attestation/sgx:age_main --copt=-O3 -- \
--start_age \
--use_fake_pce \
--age_path="${AGE_PATH}"