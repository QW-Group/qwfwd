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
