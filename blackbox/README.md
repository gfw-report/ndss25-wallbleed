# Blackbox

The C code in this directory is our attempt to
reverse-engineer the faulty DNS query processing algorithm that caused Wallbleed.
**It reproduces the behavior of the DNS injectors affected by Wallbleed in all important respects.**
If `PATCHED` is `false`, the code implements the `Wallbleed v1` vulnerability;
if `true`, the partially patched Wallbleed v2 (see [Section III-C](https://gfw.report/publications/ndss25/en/#sec:3c-Incomplete-patch-wallbleed-v2) and [Section VII](https://gfw.report/publications/ndss25/en/#sec:7-monitoring-the-censors-patching-behavior)).

This code, along with comments, is also available in [Appendix B](https://gfw.report/publications/ndss25/en/#app:b-reverse-engineered-dns-parsing-and-injection-algorithm) of our paper.

```sh
make
./blackbox
./blackbox -patched
```

## Credits

David Fifield made the most contributions in these reverse-engineering efforts.
