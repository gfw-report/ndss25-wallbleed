# Introduction

This directory contains the ordered forged IPv4 IP address pools and IPv6 IP address pools by the GFW's Injector 3. As explained in [the Appendix of the paper](https://gfw.report/publications/ndss25/en/#an-example-ordered-pool-of-fake-ip-address):

> Below are the ordered lists of 592 IPv4 and 30 IPv6 addresses used by the Wallbleed-affected DNS injectors when forging responses to A and AAAA queries, respectively, for the DNS name 4.tt. The pools for other injectors and other query names may differ [8 § 3.2] [9 § 5.2]. When an injector process injects a DNS response, it takes the next IP address from its ordered list, cycling back to the beginning after reaching the end. This fact becomes evident when collecting injected responses at a sufficiently high sample rate (around 100 packets per second or more). The selection of a “first” address in each cycle is arbitrary.

There are also `recover.py` and `Makefile` that are used to derived the ordered pools. There is also a CLI tool to determine if a DNS query's answer is in these two pools.
