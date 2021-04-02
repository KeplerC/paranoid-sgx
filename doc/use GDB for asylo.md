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

## Run in GDB 

This tutorial is how to run this project with debugging information in gdb. 



#### Step1: Get Docker Image 

```
docker run -it --rm \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    keplerc/paranoid-asylo:intel-sdk 
```

Note that we need a different tag name that has intel-sdk installed. 



#### Compile 

Compile the loader by 

```
$ bazel build  -c dbg  //src:hello_world_loader
INFO: Analyzed target //src:hello_world_loader (0 packages loaded, 0 targets configured).
INFO: Found 1 target...
Target //src:hello_world_loader_sgx_sim up-to-date:
  bazel-out/k8-dbg-ST-b8b7b2b153c1/bin/src/hello_world_loader_sgx_sim
INFO: Elapsed time: 0.071s, Critical Path: 0.00s
INFO: 1 process: 1 internal.
INFO: Build completed successfully, 1 total action
```

Note the path to the loader is `bazel-out/k8-dbg-ST-b8b7b2b153c1/bin/src/hello_world_loader_sgx_sim`



Then compile the enclave by 

```
$  bazel build  -c dbg  //src:hello_enclave.so
```



#### Run in GDB

```
$ sgx-gdb --args bazel-out/k8-dbg-ST-b8b7b2b153c1/bin/src/hello_world_loader_sgx_sim 

...(GDB Stuff, ignore the warnings)

(gdb) run --payload="hello" --enclave_path bazel-bin/src/hello_enclave_sgx_sim.so
```


bazel build  -c dbg  //src:hello_world_loader && bazel build  -c dbg  //src:hello_enclave.so
