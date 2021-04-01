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

## Run YCSB traces 

This tutorial is how to generate YCSB traces. 

```bash
git clone https://github.com/cocoppang/ShieldStore
cd ShieldStore/YCSB
./trace_gen.sh
```

The trace files are generated in YCSB's root folder. 


## Details

1. python's path: You may need to change `YCSB/bin/ycsb`'s python path to your own python path. I think it only works for Python2. 
2. Reduce the number of records generated: you need to change `YCSB/workloads/workloadX` file. There are `recordcount` and `operationcount`. They can be 1000 by default. 