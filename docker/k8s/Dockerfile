FROM gcr.io/asylo-framework/asylo

ARG USER
ARG PASS

ADD https://github.com/intel/linux-sgx/archive/sgx_2.4.tar.gz /tmp/

RUN apt-get update && \
    apt-get install -y \
        autoconf \
        automake \
        build-essential \
        gawk \
        libprotobuf-dev \
        libssl-dev \
        libtool \
        ocaml \
        ocaml-nox \
        ocamlbuild \
        protobuf-compiler \
        python \
        wget && \
    tar -C /tmp -xzf /tmp/sgx_2.4.tar.gz && \
    cd /tmp/linux-sgx-sgx_2.4 && \
    gawk -i inplace \
        '/^def newobj_handler/{r=1} \
         /^$/{ \
             if(r) { \
                 print "def newobj_handler(event):"; \
                 print "    if newobj_handler.once:"; \
                 print "        sgx_debugger_init()"; \
                 print "        newobj_handler.once=False"; \
                 print "    return"; \
                 print "newobj_handler.once=True" \
            } \
            r=0 \
        } \
        {if(!r)print $0}' \
        sdk/debugger_interface/linux/gdb-sgx-plugin/gdb_sgx_plugin.py && \
    ./download_prebuilt.sh && \
    make sdk_install_pkg && \
    linux/installer/bin/sgx_linux_x64_sdk_2.4.100.48163.bin --prefix=/opt/intel

RUN apt-get update && \
    apt-get install -y \
        binutils \
        gdb

ENV PATH=${PATH}:/opt/intel/sgxsdk/bin:/opt/intel/sgxsdk/bin/x64

RUN apt-get install -y libzmq3-dev

WORKDIR /
ADD paranoid-sgx /paranoid-sgx
WORKDIR /paranoid-sgx
RUN bazel build //src:hello_world_sgx_sim  -- 
CMD ["./scripts/run-worker.sh"]