# self_encryption

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Documentation|
|:---:|:-----------:|
|[![](https://img.shields.io/crates/v/self_encryption.svg)](https://crates.io/crates/self_encryption)|[![Documentation](https://docs.rs/self_encryption/badge.svg)](https://docs.rs/self_encryption)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that takes a set of bytes and returns a secret key derived from those bytes, and a set of encrypted chunks.

**Important Security Note**: While this library provides very secure encryption of the data, the returned secret key **requires the same secure handling as would be necessary for any secret key**.

![image of self encryption](https://github.com/maidsafe/self_encryption/blob/master/img/self_encryption.png?raw=true)

## Documentation
- [Self Encrypting Data Whitepaper](https://docs.maidsafe.net/Whitepapers/pdf/SelfEncryptingData.pdf)
- [Process Overview Video](https://www.youtube.com/watch?v=Jnvwv4z17b4)

## Usage

The library can be used through either Rust or Python interfaces.

### Rust Usage

#### Installation

Add this to your `Cargo.toml`:
```toml
[dependencies]
self_encryption = "0.30"
```

#### Example Using Basic Encryptor

```bash
# Encrypt a file
cargo run --example basic_encryptor -- -e <full_path_to_any_file>

# Decrypt a file
cargo run --example basic_encryptor -- -d <full_path_to_secret_key> <full_destination_path_including_filename>
```

### Python Usage

#### Installation

```bash
pip install self-encryption
```

#### Basic In-Memory Example

```python
from self_encryption import encrypt_bytes, decrypt_chunks

# Create test data (must be at least 3 bytes)
data = b"Hello World" * 1024  

# Encrypt the data
data_map, chunks = encrypt_bytes(data)

# Decrypt and verify
decrypted = decrypt_chunks(data_map, chunks)
assert data == decrypted
```

#### File-Based Example with Chunk Storage

```python
from self_encryption import encrypt_file, decrypt_from_files

# Encrypt file and store chunks
data_map, chunk_files = encrypt_file("input.txt", "chunks_dir")

# Decrypt from stored chunks
decrypt_from_files("chunks_dir", data_map, "output.txt")
```

#### Streaming Interface Example

```python
from self_encryption import StreamSelfEncryptor, StreamSelfDecryptor

# Stream encryption
encryptor = StreamSelfEncryptor("input_file.dat", chunk_dir="chunks_dir")
chunks = []
data_map = None

while True:
    chunk, maybe_data_map = encryptor.next_encryption()
    if chunk is None:
        data_map = maybe_data_map
        break
    chunks.append(chunk)

# Stream decryption
decryptor = StreamSelfDecryptor("output_file.dat", data_map)
for chunk in chunks:
    is_complete = decryptor.next_encrypted(chunk)
    if is_complete:
        break
```

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking Exception

self_encryption is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify self_encryption, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
