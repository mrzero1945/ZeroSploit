# ZeroSploit

An Android network security auditing toolkit. Discovers hosts on a segment,
fingerprints the services they run, matches detected versions against known
CVEs, and — when the device is rooted — exercises the lower layers that ordinary
scanners cannot reach.

Written for **authorized testing only**. See [Scope and legal use](#scope-and-legal-use).

## Features

| Area | Capabilities |
| --- | --- |
| Reconnaissance | Interface/CIDR enumeration, ARP + TCP host discovery, device classification from OUI and banners, UDP traceroute |
| Scanning | Multi-threaded TCP port scan with open/closed/filtered states, service banner fingerprinting, TLS inspection |
| Assessment | Local CVE matching against detected product/version pairs, credential auditing for telnet/SSH/HTTP |
| Traffic analysis | DNS parsing, TLS handshake dissection, cleartext credential sniffing across ~20 protocols |
| Active testing *(root)* | MITM via ARP poisoning, raw packet forging (TCP/UDP/ICMP/ARP/802.11), DNS spoofing, 802.11 monitor mode, deauth, station enumeration |

Unprivileged features work on any device. Anything needing `AF_PACKET`, raw IP
sockets, or monitor mode is gated behind an explicit root check and reports a
clear reason when unavailable, rather than failing silently.

## Requirements

- Android 7.0 (API 24) or newer
- Android SDK 35, NDK `27.0.12077973`, CMake `3.22.1`
- JDK 17
- Optional: a root manager (Magisk, KernelSU, APatch, or SuperSU) for active testing

## Building

```sh
git clone https://github.com/mrzero1945/ZeroSploit.git
cd ZeroSploit
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/` as
`ZeroSploit-debug-1.0.0-debug.apk`.

Release builds sign with a debug key unless you provide your own:

```sh
# keystore.properties in the repo root
storeFile=/path/to/keystore.jks
storePassword=...
keyAlias=...
keyPassword=...
./gradlew assembleRelease
```

`keystore.properties` is untracked. Do not commit it.

## Architecture

```
app/src/main/cpp/       Native engine (C++20)
  zs_engine.cpp           discovery, scanning, fingerprinting, CVE matching
  zs_jobs.cpp             job manager — one thread per operation, cooperative cancel
  zs_sniff.cpp            protocol credential parsers
  zs_dns.cpp  zs_tls.cpp  DNS and TLS dissectors
  zs_raw.cpp              root-gated raw socket, MITM, and 802.11 paths
  zs_helper.cpp           the privileged helper executable
  zs_jni.cpp              JNI bridge
  tests/                  host-only unit tests for the parsers and builders

app/src/main/java/com/zerosploit/
  core/                   Engine, Native, ScanService, State, Wifi, PortCache
  ui/                     screens and design tokens
  util/                   JSON helpers

design/                  Python tooling that generates icons and screen assets
```

### Job model

Every long-running operation is a `Job` with its own `std::thread`. Jobs stream
`Event` records back to Java, which the JNI layer marshals onto an
attached thread. Cancellation is cooperative — an atomic flag polled between
units of work — so a stopping scan releases its sockets promptly instead of
running to completion.

### Why the helper is a separate executable

The privileged helper (`zsraw`) is a standalone binary, not a JNI entry point.
`su` starts a *new* process as uid 0, so the app process itself can never open
`AF_PACKET` no matter what it is granted. The helper is shipped in the APK's
assets, unpacked to the app's private files directory on first launch, and
invoked as `su -c "<filesDir>/zsraw <args>"`.

It cannot live in `jniLibs`: AGP packages only `add_library()` targets, and with
`extractNativeLibs=false` there is no `lib/` directory on disk to exec from.
Assets are always readable, so the binary is copied out manually.

The whole project links the STL statically (`ANDROID_STL=c++_static`). The
helper is unpacked into `filesDir`, where no `libc++_shared.so` exists; a
shared STL would fail to start there.

### Test suite

The native unit tests build with the host toolchain and are not part of the APK:

```sh
cmake -S app/src/main/cpp -B build-host -DZS_BUILD_TESTS=ON
cmake --build build-host && ctest --test-dir build-host
```

> **Note:** `app/build.gradle` and `app/src/main/cpp/CMakeLists.txt` reference
> `tools/make-keystore.sh` and `tests/run_tests.sh` in their comments. Those
> scripts are not present in this repository; use the CMake invocation above.

## Scope and legal use

This tool performs ARP poisoning, WiFi deauthentication, credential brute
forcing, and traffic interception. Running any of that against a network you do
not own or have written permission to test is illegal in most jurisdictions and
will get an account takedown notice regardless of intent.

- Test only hardware and networks you own or have explicit, documented authorization to assess.
- ARP poisoning and deauth affect *every* device on the segment, including bystanders. On shared or public networks this is a denial-of-service against uninvolved people.
- Credential auditing and traffic sniffing capture real secrets. Treat any output as sensitive: store it encrypted, keep it out of version control, and destroy it when the engagement ends.
- Do not use findings against systems outside the agreed scope.

This software is provided under the [GPL-3.0 License](LICENSE). It comes with
no warranty and no liability for how you use it.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE) for the full text.

The quick summary: you may use, study, modify, and redistribute this software.
If you distribute it, or if you run a modified version over a network, you must
release your source under the same license.