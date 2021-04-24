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

This guide demonstrates using Asylo to run on multiple physical AWS instances. 

#### Step1: setup cloud environment

Run 
```bash
sudo apt update
sudo apt install -y docker.io
git clone https://github.com/KeplerC/paranoid-sgx
cd ~/paranoid-sgx
MY_PROJECT=~/paranoid-sgx
sudo docker run -it --rm --net=host \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    keplerc/paranoid-asylo:latest
```
to setup the cloud environment. 

#### Step 2: Server setup 
modify `src/common.h`. If you just want the instance to run router and coordinator, modify 
```c
#define TOTAL_THREADS 2
```
to 2. 

and then run the cloud by 
```bash
bazel run //src:hello_world_sgx_sim -- 
```

#### Step 3: Client setup
similarly, modify `src/common.h`. 
```c
// ip of this machine
#define NET_CLIENT_IP "localhost"
// ip of seed server(router)
#define NET_SEED_SERVER_IP "localhost"
// ip of sync coordinator
#define NET_SYNC_SERVER_IP "localhost"
```
to the corresponding ip addresses.

Also, modify 
```c
#define RUN_BOTH_CLIENT_AND_SERVER true
```
in `hello_driver.cc`. to `false`. Then this machine only starts clients. 

and then run the client by
```bash
bazel run //src:hello_world_sgx_sim -- 
```
