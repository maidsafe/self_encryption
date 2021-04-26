# self_encryption

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Documentation|
|:---:|:-----------:|
|[![](http://meritbadge.herokuapp.com/self_encryption)](https://crates.io/crates/self_encryption)|[![Documentation](https://docs.rs/self_encryption/badge.svg)](https://docs.rs/self_encryption)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/Convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that can be utilised in any application that provides a POSIX like filesystem interface, dealing very effectively with the content part of any data (in tests the parallelised approach can actually be faster than reading/writing data as a single stream). It is important to realise two important aspects of this library:

1. This library deals with file content **only**
2. This library provides very secure data, but does return a data structure (DataMap) that in turn requires to be secured.

![image of self encryption](https://github.com/maidsafe/self_encryption/blob/master/img/self_encryption.png?raw=true)

## Video of the process
[self_encryption process and use case video](https://www.youtube.com/watch?v=Jnvwv4z17b4)

## Whitepaper

[Self Encrypting Data](https://docs.maidsafe.net/Whitepapers/pdf/SelfEncryptingData.pdf), David Irvine, First published September 2010, Revised June 2015.

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

### Linking exception

self_encryption is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify self_encryption, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
