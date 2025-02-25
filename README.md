# Wallbleed Artifacts

This repo includes the source code, data, and documentation for the NDSS 2025 paper
[*Wallbleed: A Memory Disclosure Vulnerability in the Great Firewall of China*](https://gfw.report/publications/ndss25/en/).

It is designed for anyone who is curious about the methodologies and additional details in our study.

Due to the large number of tools, data, and documents, we plan to release them gradually in this repository. As of February 26, 2025, we are still in the process of adding more content, so stay tuned for further updates.

## Overview of the Repo Structure

```txt
.
├── LICENSE
├── README.md
└── blackbox
```

* [blackbox](./blackbox/) contains **the equivalent C code that reproduces the behaviors of the DNS injectors affected by Wallbleed v1 and Wallbleed v2 in all important respects.**
