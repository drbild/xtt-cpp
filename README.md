# XTT-CPP: C++ wrappers for the XTT IoT security protocol

This project provides two C++ APIs for the C-based XTT
reference implementation [here](https://github.com/xaptum/xtt):
- `libxtt-cpp`:
  - A mostly-one-to-one C++ version of the C API provided by [here](https://github.com/xaptum/xtt)
- `libxtt-asio`:
  - A higher-level API that builds upon `libxtt-cpp` and uses the [Boost ASIO](https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio.html)
    perform all necessary network I/O asynchronously

# Project Status
[![Build Status](https://travis-ci.org/xaptum/xtt-cpp.svg?branch=master)](https://travis-ci.org/xaptum/xtt-cpp)

## Installation

`xtt-cpp` is available for the following distributions. It may also be
built from source.

### Debian (Jessie or Stretch)

``` bash
# Install the Xaptum API repo GPG signing key.
apt-get adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca

# Add the repository to your APT sources, replacing <dist> with either jessie or stretch.
echo "deb http://dl.bintray.com/xaptum/deb <dist> main" > /etc/apt/sources.list.d/xaptum.list

# Install the library.
sudo apt-get install libxtt-cpp-dev libxtt-asio-dev
```

### Homebrew (MacOS)

``` bash
# Tap the Xaptum Homebrew repository.
brew tap xaptum/xaptum

# Install the library.
brew install xtt-cpp xtt-asio
```

## Installation from Source

### Build Dependencies

* CMake (version 3.0 or higher)
* A C99-compliant compiler

* [XTT](https://github.com/xaptum/xtt) (version 0.6.0 or higher)

### Building the Library

```bash
# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build the library
cmake --build .

# Run the tests
ctest -V
```

### CMake Options

The following CMake configuration options are supported.

| Option                              | Values          | Default    | Description                                     |
|-------------------------------------|-----------------|------------|-------------------------------------------------|
| CMAKE_BUILD_TYPE                    | Release         |            | With full optimizations.                        |
|                                     | Debug           |            | With debug symbols.                             |
|                                     | RelWithDebInfo  |            | With full optimizations and debug symbols.      |
| CMAKE_INSTALL_PREFIX                | <string>        | /usr/local | The directory to install the library in.        |
| BUILD_EXAMPLES                      | ON, OFF         | OFF        | Build example programs                          |
| BUILD_SHARED_LIBS                   | ON, OFF         | ON         | Build shared libraries.                         |
| BUILD_STATIC_LIBS                   | ON, OFF         | OFF        | Build static libraries.                         |
| BUILD_TESTING                       | ON, OFF         | ON         | Build the test suite.                           |
| STATIC_SUFFIX                       | <string>        | <none>     | Appends a suffix to the static lib name.        |

### Installing

```bash
cd build
cmake --build . --target install
```

## Usage
```
#include <xtt/cpp.h>
#include <xtt/asio.h>
```
TODO: Add simple client and server source code

### Example Programs
If the `-DBUILD_EXAMPLES=ON` CMake option is used during building,
example client and server executables will be built and placed
in the `${CMAKE_BINARY_DIR}/bin` directory.
Example configuration data is also provided in the `examples/data`
directory.

#### Server
To run the example server, first copy the necessary example data
into the working directory:
```bash
cp ${xtt_root_directory}/examples/data/server/* .
```

The server executable takes the TCP port to use as parameter:
```bash
xtt_asio_server 4444
```

The server will then listen on that port for incoming identity-provisioning
requests, service them,
and output the agreed-upon identity information exchanged with the client.

# License
Copyright 2018 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
