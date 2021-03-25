<!--jekyll-front-matter
---

title: Quickstart Guide

overview: Install Asylo, build, and run your first enclave!

location: /_docs/guides/quickstart.md

order: 10

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide demonstrates using Asylo to protect secret data from an attacker with
root privileges.

## Run in SGX mode

This assumes SGX driver is installed. The newest version works. The tutorial of installing Intel SGX driver can be found in https://github.com/google/asylo/blob/master/INSTALL.md#intel-sgx-hardware-backend-support. 

To verify the SGX driver for the docker and 
to set environment variable, use the following script: 
```bash
function determine_sgx_device {
    export SGXDEVICE="/dev/sgx"
    export MOUNT_SGXDEVICE="--device=/dev/sgx"
    if [[ ! -e "$SGXDEVICE" ]] ; then
        export SGXDEVICE="/dev/isgx"
        export MOUNT_SGXDEVICE="--device=/dev/isgx"
        if [[ ! -c "$SGXDEVICE" ]] ; then
            echo "Warning: No SGX device found! Will run in SIM mode." > /dev/stderr
            export MOUNT_SGXDEVICE=""
            export SGXDEVICE=""
        fi
    fi
}
determine_sgx_device
echo The hardware is $SGXDEVICE
```

After set variable $SGXDEVICE$, we can launch SGX enabled docker by 
```bash
MY_PROJECT=~/paranoid-sgx
docker run $MOUNT_SGXDEVICE \
    -it --rm \
    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    keplerc/paranoid-asylo:latest 
```
and run by 
```
bazel run //src:hello_world_sgx_hw -- --names="visitor"
```