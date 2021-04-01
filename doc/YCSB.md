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

This tutorial is how to generate YCSB traces. 

```bash
git clone https://github.com/cocoppang/ShieldStore
cd ShieldStore/YCSB
./trace_gen.sh
```

The trace files are generated in YCSB's root folder. 