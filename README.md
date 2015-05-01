# self_encryption

**Self encrypting files (convergent encryption plus obfuscation)**


|Crate|Travis|Appveyor|Coverage|
|:------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/self_encryption)](https://crates.io/crates/self_encryption)|[![Build Status](https://travis-ci.org/dirvine/self_encryption.svg?branch=master)](https://travis-ci.org/dirvine/self_encryption)|[![Build status](https://ci.appveyor.com/api/projects/status/qveqoe45n56atlk7?svg=true)](https://ci.appveyor.com/project/dirvine/self-encryption) | [![Coverage Status](https://coveralls.io/repos/dirvine/self_encryption/badge.svg?branch=master)](https://coveralls.io/r/dirvine/self_encryption?branch=master)|

| [API Documentation](http://dirvine.github.io/self_encryption/self_encryption/) | [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/Convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that can be utilised in any application that provides a POSIX like filesystem interface, dealing very effectively with the content part of any data (in tests the parallelised approach can actually be faster than reading/writing data as a single stream). It is important to realise two important aspects of this library:

1. This library deals with file content **only**
2. This library provides very secure data, but does return a data structure (DataMap) that in turn requires to be secured.

![image of self encryption] (https://github.com/dirvine/self_encryption/blob/master/img/self-encryption.png?raw=true)

## ToDo list

- [x] Initial structure
- [x] Test set-up
- [x] Travis integration
- [x] Docs creation
- [x] Docs hosting (github.io)
- [x] Windows CI set-up (ci.AppVeyor.com)
- [x] Read/Write file in memory based buffer
- [x] API version 0.0.8
- [x] Implement disk based interface as example
- [x] Full unit tests in lib.rs
- [x] Integrations tests in tests module
- [x] Benchmark tests for varying file sizes from 1 byte to 10 M/b
- [x] API stable version 0.1.0
- [ ] Add compression pre encrypt and post encrypt in encrypt and decrypt methods
- [ ] Add task passing to allow cores to be lit up when handling chunks
- [ ] Allow any size file
    - [ ] Replace sequencer with new struct and use BufferedStream to offload to disk (MemoryMapped file)
    - [ ] Clean up any cache chunks when disk space is low (start + now < 90%)
    - [ ] Store intermediate chunks when disk space is low (start + now < 90%)
- [ ] Add another functor to constructor to allow storage query for chunks (not get)
- [ ] Check for first last middle chunks on net and presume file stored
- [x] Coverage analysis (coveralls ?)
- [ ] Uncomment benchmark tests read methods (require bench in beta channel or stabilised first)

#Video of the process 
[self_encryption process and use case video] (https://www.youtube.com/watch?v=Jnvwv4z17b4)

#Basic self_encryptor example DIY instructions

Instructions to use the 'basic_encryptor' example to encrypt a file into encrypted chunks and a datamap and then decrypted the datamap and restore the file.

1. install rust Nightly (the compiler) http://www.rust-lang.org/install.html or on mac / linux
    `curl -s https://static.rust-lang.org/rustup.sh | sudo sh -s -- --channel=nightly`

2. install gcc ( linux `sudo apt-get install gcc` / windows [one example](http://tdm-gcc.tdragon.net/download) )

3. clone self_encryption (install git if you don't have it `sudo apt-get install git` on linux)
    `git clone http://github.com/dirvine/self_encryption.git`

4. go into the folder:
    `cd self_encryption`

5. encrypt a file with the example `basic_encryptor` by
    `cargo run --example basic_encryptor -- -e <full_path_to_my_file>`

You now have the executable in `../self_encryption/target/debug/examples/` your data_map and folder with the encrypted chunks is written where you ran the example from.

1. to decrypt your file, run
    `cargo run --example basic_encryptor -- -d <full_path_to>/data_map <full_destination_path_including_filename>` 

This will restore your file.
