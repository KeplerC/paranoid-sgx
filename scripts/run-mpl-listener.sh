kill -9 $(lsof -Pi :1234 -sTCP:LISTEN -t)
bazel run //src:mpl_listener_sgx_hw --copt=-O3
