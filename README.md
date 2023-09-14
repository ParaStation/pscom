# ParaStation Communication Library
* [Installation](#installation)
    * [Prerequisites](#prerequisites)
        * [Required](#required)
        * [Optional](#optional)
            * [Hardware-dependent](#hardware-dependent)
            * [Other](#other)
    * [Build configuration](#build-configuration)
        * [Install prefix / location](#install-prefix-location)
        * [Build type](#build-type)
        * [Plugins](#plugins)
        * [CUDA awareness](#cuda-awareness)
        * [Unit tests](#unit-tests)
        * [Code coverage analysis](#code-coverage-analysis)
    * [Build & Install](#build-install)
    * [Environment variables](#environment-variables)
    * [Contributing](#contributing)
    * [More documentation](#more-documentation)

The ParaStation Communication Library (`pscom` for short) is an open-source low-level communication library, especially designed for the employment in HPC systems.

# Installation

This guide describes the installation of `pscom` to a custom location `/path/to/pscom/install/dir/` on your system.
For installations of ParaStation MPI, this directory is typically a global directory called `/opt/parastation/`.

## Prerequisites

### Required
- CMake, at least version 3.10
- C compiler with C99 support
- `popt` library, a command line option parsing library

### Optional

#### Hardware-dependent
- IB Vebs library for plugin OpenIB
- UCP library for plugin UCP
- Portals4 library for plugin Portals (BXI support)
- PSM2 library for plugin PSM
- Extoll and Velo libraries for plugins Extoll and Velo
- DAPL library for plugin DAPL
- CUDA libraries for CUDA awareness of `pscom`

#### Other
- Parastation Management (`psmgmt`) library
- cmocka Library for unit tests

If CMake does not detect a library on your system that is required for a plugin or feature you want to use, check if the install directory of that library is contained in your system's and compiler's library and header environment paths, e.g., `LIBRARY_PATH`, `LD_LIBRARY_PATH`, `PATH`, and `C_PATH`.
Alternatively, for some libraries it is possible to specify the local install directory in your system by passing the following options to CMake:

| Library | CMake option      | Default value       |
|---------|-------------------|---------------------|
| CUDA    | `-DCUDA_HOME`     | `/usr/local/cuda`   |
| popt    | `-DPOPT_HOME`     | `/usr`              |
| Extoll  | `-DEXTOLL_HOME`   | `/opt/extoll/x86_64`|
| PSM2    | `-DPSM2_HOME`     | `/usr`              |
| UCP     | `-DUCP_HOME`      | `/usr`              |
| Portals4| `-DPORTALS4_HOME` | `/usr`              |


## Build configuration

### Install prefix / location
To install `pscom` in a custom location, pass `-DCMAKE_INSTALL_PREFIX=pscom/install/dir/` to CMake.
Default install location is `/usr/local` on UNIX, see [here](https://cmake.org/cmake/help/v3.24/variable/CMAKE_INSTALL_PREFIX.html).
This location will be used, if `CMAKE_INSTALL_PREFIX` is not explicitly set.

### Build type

Currently, `pscom` offers 5 different build types

 Build Type & `CMAKE_BUILD_TYPE` value   | Purpose |
|---------------|-----------------------------------|
| None          | No debug info or optimizations |
| Debug         | Debug info, few optimizations without interference with debugging |
| Release       | No debug info (esp. no assertions), aggressive optimization |
| RelWithDebInfo (default)    | Debug info (esp. assertions), aggressive optimization |
| MinSizeRel    | Debug info, code size optimized |

Set the value of `-DCMAKE_BUILD_TYPE=<selected build type>` to select a build type different than the default.

### Plugins
CMake auto-detects which headers and libraries are present on your system and disables all plugins for which the requirements cannot be met.
A respective summary of enabled/ disabled plugins is printed at the end of the CMake run.
If you want to disable a plugin explicitly (even if requirements are met by your system), you can pass the option `-D<plugin name>_ENABLED=0` to CMake, for example `-DPSM2_ENABLED=0` to disable the PSM plugin.

For runtime configuration options of plugins including customization of their priorities, see [here](./doc/RuntimeConfig.md#plugin-options).

### CUDA awareness
If the CUDA library is found on your system, `pscom` is automatically compiled with CUDA awareness features enabled.
If you want to disable CUDA awareness, you can pass `-DCUDA_ENABLED=0` to CMake.

### Unit tests
To enable the unit tests, pass `-DUTEST_ENABLED=1` to CMake. Unit tests require the cmocka library.

### Code coverage analysis
Code coverage analysis is only available if unit tests are enabled. The feature is disabled by default. To enable code coverage analysis, pass `-DCOVERAGE_ENABLED=1` to CMake.

## Build & install
It is highly recommended to run CMake from a separate folder.
In the top level `pscom` directory, execute

```console
$ mkdir build
$ cd build
```

Execute from within this newly created folder

```console
$ cmake <your config parameters here> ..
$ make
```

Cmake will report any missing dependencies. Check the output of CMake carefully.

**Example:** To compile `pscom` with installation directory `/opt/parastation` run

```console
$ cmake -DCMAKE_INSTALL_PREFIX=/opt/parastation ..
$ make
```
Finally, to install `pscom` in your system (superuser rights might be required depending on the install location), run

```console
$ make install
```

## Environment variables

If you have installed `pscom` to a custom location, you need to add this custom path to your system's environment variables so that other sofware - for example ParaStation MPI - can find and work with `pscom`.

```console
$ export LIBRARY_PATH=pscom/install/dir/lib[64]:${LIBRARY_PATH}
$ export LD_LIBRARY_PATH=pscom/install/dir/lib[64]:${LD_LIBRARY_PATH}
$ export CPATH=pscom/install/dir/include:${CPATH}
$ export PATH=pscom/install/dir/bin:${PATH}
```

## Contributing
To ensure that all commits conform to the coding style, the pre-commit hook should be activated. Therefore, you have to link this hook from the top-level source directory:
```console
$ ln -s ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

This automatically runs `clang-format` on all changed files. Currently, we rely on `clang-format` in version 16.0.6 for checking the coding style.

## More documentation
- [Introduction and Concepts](doc/PscomConcepts.md)
- [Repository Structure](doc/RepoStructure.md)
- [Runtime Configuration Options](doc/RuntimeConfig.md)
- [API and Internals](doc/PscomInterface.md)
