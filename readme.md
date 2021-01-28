### gnutls-example  
 Chris Pilkington  
 Copyright (C) 2021-present  
 [http://chris.iluo.net/](http://chris.iluo.net/)

### License

Copyright (C) 2021  Chris Pilkington

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

### What is this?

Just a simple example of using gnutlsxx (A simple wrapper of gnutls) to connect to host via TLS to (Very naively) make a basic HTTP request.  
It is really just an example of using TLS with gnutls.  OpenSSL has a bloated and horrible API and I was curious what it would look like with a simpler, more modern API.

### gnutlsxx

I used gnutlsxx which comes with gnutls.  It is a very thing layer over gnutls, basically just providing a nice RAII interface over the top of the C functions.  Many of the C++ functions have a 1 to 1 mapping with their underlying C API.

## Building

### Get a copy of the project

`git clone git@github.com:pilkch/gnutls-example.git`  
OR  
`git clone https://github.com/pilkch/gnutls-example.git`  

### Building on Linux

NOTE: I've only tried it on Ubuntu.  The libgnutls development package name may be different on your distribution.

Install prerequisites:
```bash
sudo apt-get install cmake libgnutls28-dev
```

Build:
```bash
cmake .
make
```

### Run

```bash
./gnutls-example
```

It writes the returned HTTP content to output.html.  It is very dumb, if it receives a 404 not found, or 301 moved permanently for example it will fail.  It pretty much has to get a 200 response.

If you get an error about file not found then you may need to modify "ca_certificates_file_path" in main.cpp to point to your system ca-certificates file.

### Credit

This example was created by me from these bits of code, I basically just expanded upon the first one, adding *slightly* more rhobust HTTP parsing and TCP connection handling:

#### gnutls Client example using the C++ API

This project is basically a complete working example based on this code:  
[https://gnutls.org/manual/html_node/Client-example-in-C_002b_002b.html](https://gnutls.org/manual/html_node/Client-example-in-C_002b_002b.html)

#### TCP Helper Functions

[https://gnutls.org/manual/html_node/Helper-functions-for-TCP-connections.html](https://gnutls.org/manual/html_node/Helper-functions-for-TCP-connections.html)
 