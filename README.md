# self_encryption

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/self_encryption)](https://crates.io/crates/self_encryption)|[![Documentation](https://docs.rs/self_encryption/badge.svg)](https://docs.rs/self_encryption)|[![Build Status](https://travis-ci.org/maidsafe/self_encryption.svg?branch=master)](https://travis-ci.org/maidsafe/self_encryption)|[![Build status](https://ci.appveyor.com/api/projects/status/htljxqrosx1i237s/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/self-encryption/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/self_encryption.png?label=ready&title=Ready)](https://waffle.io/maidsafe/self_encryption)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/Convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that can be utilised in any application that provides a POSIX like filesystem interface, dealing very effectively with the content part of any data (in tests the parallelised approach can actually be faster than reading/writing data as a single stream). It is important to realise two important aspects of this library:

1. This library deals with file content **only**
2. This library provides very secure data, but does return a data structure (DataMap) that in turn requires to be secured.

![image of self encryption](https://github.com/maidsafe/self_encryption/blob/master/img/self-encryption.png?raw=true)

## Video of the process
[self_encryption process and use case video](https://www.youtube.com/watch?v=Jnvwv4z17b4)

## Examples

### Using `self_encryptor`

This library splits a file into encrypted chunks and also produces a data map for the same. This data map with encrypted chunks enables the file to be reconstituted. Instructions to use the 'basic_encryptor' example are as follows:

##### Encrypt a file:

    cargo run --example basic_encryptor -- -e <full_path_to_any_file>

You should now have the example binary in `../self_encryption/target/debug/examples/`. The `data_map` for the given file and it's encrypted chunks will be written to the current directory.

##### Decrypt a file:

    cargo run --example basic_encryptor -- -d <full_path_to_data_map> <full_destination_path_including_filename>

This will restore the original file to the given destination path.

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).
