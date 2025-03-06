# Wallbleed Artifacts

This repo includes the source code, data, and documentation for the NDSS 2025 paper
[*Wallbleed: A Memory Disclosure Vulnerability in the Great Firewall of China*](https://gfw.report/publications/ndss25/en/).

It is designed for anyone who is curious about the methodologies and additional details in our study.

Due to the large number of tools, data, and documents, we plan to release them gradually in this repository. As of March 6, 2025, we are still in the process of adding more content, so stay tuned for further updates.

## Overview of the Repo Structure

```txt
tree -L2d
.
├── blackbox
└── util
    └── is-forged-response
```

* [blackbox](./blackbox/) contains **the equivalent C code that reproduces the behaviors of the DNS injectors affected by Wallbleed v1 and Wallbleed v2 in all important respects.**
* [util/is-forged-response] contains the GFW's Injector 3's forged IPv4 answer pools and IPv6 answer pools. It also contains code and Makefile that derived these files, as well as a CLI tool to determine if a DNS query's answer is in the pool.
