# QWFWD: a QuakeWorld server proxy


## Supported architectures

The following architectures are fully supported by **[QTV][qtv]** and are available as prebuilt binaries:
* Linux amd64 (Intel and AMD 64-bits processors)
* Linux i686 (Intel and AMD 32-bit processors)
* Linux aarch (ARM 64-bit processors)
* Linux armhf (ARM 32-bit processors)
* Windows x64 (Intel and AMD 64-bits processors)
* Windows x86 (Intel and AMD 32-bit processors)

## Prebuilt binaries
You can find the prebuilt binaries on [this download page][qwfwd-builds].

## Prerequisites

None at the moment.

## Building binaries

### Build from source with CMake

Assuming you have installed essential build tools and ``CMake``
```bash
mkdir build && cmake -B build . && cmake --build build
```
Build artifacts would be inside ``build/`` directory, for unix like systems it would be ``qwfwd``.

You can also use ``build_cmake.sh`` script, it mostly suitable for cross compilation
and probably useless for experienced CMake user.
Some examples:
```
./build_cmake.sh linux-amd64
```
should build QWFWD for ``linux-amd64`` platform, release version, check [cross-cmake](tools/cross-cmake) directory for all platforms

```
B=Debug ./build_cmake.sh linux-amd64
```
should build QWFWD for linux-amd64 platform with debug

```
V=1 B=Debug ./build_cmake.sh linux-amd64
```
should build QWFWD for linux-amd64 platform with debug, verbose (useful if you need validate compiler flags)

```
G="Unix Makefiles" ./build_cmake.sh linux-amd64
```

force CMake generator to be unix makefiles

```
./build_cmake.sh linux-amd64
```

build QWFWD for ``linux-amd64`` version, you can provide
any platform combinations.

## Source-port probing

PathProbe tests UDP source ports on the proxy and keeps the socket with the
lowest valid ping RTT, using the same minimum-RTT selection principle as
ezQuake. Configure it in `qwfwd.cfg`:

```
sv_pathprobe_enable 1
sv_pathprobe_count 64
sv_pathprobe_delay 1000
```

`sv_pathprobe_count` defaults to 64 and is clamped to 1–64 candidates, including
the existing source port. Additional sockets are only opened while the shared
active probe count is below 64; existing sockets can still be tested when that
limit is reached. Concurrent connections can therefore get fewer candidates
than requested. Each candidate gets
up to three ping requests, one outstanding request at a time. Selection waits
for all three valid replies per candidate or the overall deadline.
`sv_pathprobe_delay` is that deadline in milliseconds, not a delay between
requests; nonpositive values use 1000 ms and values above 10000 are capped.
At the deadline, candidates with fewer replies remain eligible; the output
reports the winning candidate's actual reply count. With no valid replies,
the original socket is retained.

Only a one-byte `A2A_ACK` from the target IP and port counts as a reply. Queued
duplicates are drained before sending the next request. QW's ACK carries no
request identifier, so a delayed duplicate arriving after the next request
cannot be distinguished from its reply.

Example output (illustrative):

```
[qwfwd] Source port 48327: min proxy-server RTT 11.52 ms (3/3 replies, 32 ports)
```

This is the minimum measured **proxy-to-server round-trip time**, excluding
the client-to-proxy path. It is not the in-game scoreboard ping. The displayed
source port is the socket's local UDP port; NAT may translate it externally.
The selected socket stays open for the connection.

Probing is enabled by default for QW. A client can opt out with
`setinfo pathprobe 0`; `sv_pathprobe_enable 0` disables it for everyone.
It is disabled for non-QW protocols.

Run the local UDP regression tests against a built binary with:

```
python3 tests/pathprobe.py build/qwfwd
```

## Versioning

For the versions available, see the [tags on this repository][qwfwd-tags].

## Authors

  deurk
  qqshka
  VVD

## Code of Conduct

We try to stick to our code of conduct when it comes to interaction around this project. See the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) file for details.

## License

This project is licensed under the GPL-2.0 License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* Thanks to the fine folks on [Quakeworld Discord][discord-qw] for their support and ideas.

[qwfwd]: https://github.com/QW-Group/qwfwd
[qwfwd-tags]: https://github.com/QW-Group/qwfwd/tags
[qwfwd-builds]: https://builds.quakeworld.nu/qwfwd
[discord-qw]: http://discord.quake.world/
