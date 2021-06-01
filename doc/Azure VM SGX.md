<!--jekyll-front-matter
---

order: 10

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide demonstrates running ParaLam on Azure DCv2_series SGX-enabled machines.

## Create Azure VM using already setup Image
Get to "Create a virtual machine page" through steps 1-3: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-portal?WT.mc_id=UI-AQC

What to fill:
https://github.com/KeplerC/paranoid-sgx/blob/main/doc/Create%20a%20virtual%20machine%20-%20Microsoft%20Azure.pdf

You can change "size" to any of DC1s_v2, DC2s_v2, DC4s_v2, or DC8_v2, based on your need.

Follow steps 10+ and connect to VM: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-portal?WT.mc_id=UI-AQC


## Should already have the Intel SGX driver installed. Check using the following command, and expect output:
```bash
dmesg | grep -i sgx
[  106.775199] sgx: intel_sgx: Intel SGX DCAP Driver {version}
```

## Run in SGX mode
To verify the SGX driver for the docker and to set environment variable, use the following script: 
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

## Setup Docker
Run 
```bash
sudo apt update
sudo apt install -y docker.io
git clone https://github.com/KeplerC/paranoid-sgx
cd ~/paranoid-sgx
```
to setup the docker environment. 

## Run Docker
Run
```
MY_PROJECT=~/paranoid-sgx
sudo docker run $MOUNT_SGXDEVICE \
    -it --rm \
    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    keplerc/paranoid-asylo:latest 
```
to run docker.

## Run scripts
Change all appearances of hello_world_sgx_sim to hello_world_sgx_hw in all scripts. E.g. ```bazel run //src:hello_world_sgx_hw --```

## Multiple Machines
Check https://github.com/KeplerC/paranoid-sgx/blob/usenix_benchmark/doc/multiple%20instances.md#step-2-server-setup
