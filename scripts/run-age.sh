# bazel build --define="SGX_SIM=0" @com_google_asylo//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_sgx_hw.so --copt=-O3

# bazel build --@com_google_asylo_backend_provider//:backend=@linux_sgx//:asylo_sgx_hw @com_google_asylo//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_sgx_hw.so

DCAP_VERSION="1.12.1" # Replace with the most up-to-date version available.
INTEL_ENCLAVES_PATH="/opt/intel_enclaves/${DCAP_VERSION}"
AGE_PATH=/home/gdpmobile5/paranoid-sgx/bazel-bin/external/com_google_asylo/asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_sgx_hw.so.runfiles/com_google_asylo/asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_sgx_hw.so
PCK_CERTIFICATE_CHAIN=`cat /home/gdpmobile5/asylo/asylo/cert_chain.textproto`
bazel run @com_google_asylo//asylo/identity/attestation/sgx:age_main_sgx_hw -- \
--start_age \
--age_path="${AGE_PATH}" \
--issuer_certificate_chain="${PCK_CERTIFICATE_CHAIN}" \
--intel_enclaves_path="${INTEL_ENCLAVES_PATH}"