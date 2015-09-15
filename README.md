# self_encryption

[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/self_encryption/blob/master/COPYING)

**Primary Maintainer:**     Brian Smith (brian.smith@maidsafe.net)

**Secondary Maintainer:**   Qi Ma (qi.ma@maidsafe.net)

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Linux/OS X|Windows|Coverage|Issues|
|:---:|:--------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/self_encryption)](https://crates.io/crates/self_encryption)|[![Build Status](https://travis-ci.org/maidsafe/self_encryption.svg?branch=master)](https://travis-ci.org/maidsafe/self_encryption)|[![Build status](https://ci.appveyor.com/api/projects/status/htljxqrosx1i237s/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/self-encryption/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/self_encryption/badge.svg)](https://coveralls.io/r/maidsafe/self_encryption)|[![Stories in Ready](https://badge.waffle.io/maidsafe/self_encryption.png?label=ready&title=Ready)](https://waffle.io/maidsafe/self_encryption)|

|[API Documentation - master branch](http://maidsafe.net/self_encryption/master)|[SAFE Network System Documention](http://systemdocs.maidsafe.net)|[MaidSafe website](http://maidsafe.net)|[Safe Community site](https://forum.safenetwork.io)|
|:------:|:-------:|:-------:|:-------:|

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/Convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that can be utilised in any application that provides a POSIX like filesystem interface, dealing very effectively with the content part of any data (in tests the parallelised approach can actually be faster than reading/writing data as a single stream). It is important to realise two important aspects of this library:

1. This library deals with file content **only**
2. This library provides very secure data, but does return a data structure (DataMap) that in turn requires to be secured.

![image of self encryption](https://github.com/maidsafe/self_encryption/blob/master/img/self-encryption.png?raw=true)

##Pre-requisite:
`libsodium` is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Install sodium by following the instructions [here](https://github.com/maidsafe/QA/blob/master/Documentation/Install_libsodium.md).

## Todo Items

### [0.2.3] - Unrestricted file sizes.
- [ ] Allow any size file
    - [ ] Replace sequencer with new struct and use BufferedStream to offload to disk (MemoryMapped file)
    - [ ] Clean up any cache chunks when disk space is low (start + now < 90%)
    - [ ] Store intermediate chunks when disk space is low (start + now < 90%)
- [ ] Add another functor to constructor to allow storage query for chunks (not get)
- [ ] Check for first last middle chunks on net and presume file stored
- [ ] Uncomment benchmark tests read methods (require bench in beta channel or stabilised first)

## Video of the process
[self_encryption process and use case video](https://www.youtube.com/watch?v=Jnvwv4z17b4)

## Examples

### Using `self_encryptor`

This library splits a file into encrypted chunks and also produces a data map for the same. This data map with encrypted chunks enables the file to be reconstituted. Instructions to use the 'basic_encryptor' example are as follows:

1. Install RUST(Nightly build).
 - OSX / Linux: `curl -s https://static.rust-lang.org/rustup.sh | sudo sh -s -- --channel=nightly`
 - Windows: Download Exe installer from http://www.rust-lang.org/install.html

2. Install gcc.
 - Linux: `sudo apt-get install gcc`
 - Windows: Any compatible gcc such as [TDM-GCC](http://tdm-gcc.tdragon.net/download)

3. Clone this repo / Download as zip and extract archive.
 - To clone via Git: `git clone http://github.com/maidsafe/self_encryption.git`

4. Browse to repo locally in terminal / command prompt.
 - `cd self_encryption`

5. Encrypt a file:
 - `cargo run --example basic_encryptor -- -e <full_path_to_any_file>`

  You should now have the example binary in `../self_encryption/target/debug/examples/`. The `data_map` for the given file and it's encrypted chunks will be written to the current directory.

6. Decrypt a file:
 - `cargo run --example basic_encryptor -- -d <full_path_to_data_map> <full_destination_path_including_filename>`

  This will restore the original file to the given destination path.
