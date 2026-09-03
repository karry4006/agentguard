# GCC Runtime Library Exception 3.1 review

This is narrow engineering evidence for the sealed RC1 image, not legal
certification. The exact Debian `gcc-14-base` copyright text records GCC
runtime libraries under GPL v3-or-later with the GCC Runtime Library Exception
3.1 (31 March 2009). The exact package md5sums and extracted RC1 files establish
the following scope:

| Component | Package version | Distributed file | SONAME | GCC source mapping | Result |
|---|---|---|---|---|---|
| `libgcc-s1` | `14.2.0-19` | `/usr/lib/x86_64-linux-gnu/libgcc_s.so.1` | `libgcc_s.so.1` | `libgcc/`, GCC unwind/thread runtime files | `CONFIRMED` |
| `libgomp1` | `14.2.0-19` | `/usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0` | `libgomp.so.1` | `libgomp/` | `CONFIRMED` |
| `libstdc++6` | `14.2.0-19` | `/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33` | `libstdc++.so.6` | `libstdc++-v3/` | `CONFIRMED` |
| `gcc-14-base` | `14.2.0-19` | package documentation/support files only | N/A | `gcc-14-base` package metadata | `NOT_APPLICABLE` |

The authoritative source text is staged at
`licenses/third-party/debian/gcc-14-base-14.2.0-19-COPYRIGHT.txt`. Binary
SHA-256 values, exact package paths, source subtrees, and the sealed RC digest
are recorded in `artifacts/gcc-runtime-exception-evidence.json`.
