# Self-Encryption - Change Log

## [0.3.1]
- Updated dependencies.

## [0.3.0]
- Updated dependencies.

## [0.2.6]
- Various bug fixes and tidy up.
- Setup clippy usage.
- Include nightly builds on travis.

## [0.2.5]
- Swap forked memory_map for original memmap crate.

## [0.2.4]
- Remove wildcards from dependencies.

## [0.2.3]
- Update in line with sodiumoxide 0.0.9 changes.

## [0.2.2]
- Increase file sizes to 1Gb using memory map (previously omitted).
- Compression pre encrypt and post encrypt in encrypt and decrypt methods
- Task passing to allow cores to be lit up when handling chunks

## [0.2.1]
- Fixed lint warnings caused by latest Rust nightly

## [0.0.0 - 0.2.0]
- Initial structure
- Test set-up
- Travis integration
- Docs creation
- Docs hosting (github.io)
- Windows CI set-up (ci.AppVeyor.com)
- Read/Write file in memory based buffer
- API version 0.0.8
- Implement disk based interface as example
- Full unit tests in lib.rs
- Integrations tests in tests module
- Benchmark tests for varying file sizes from 1 byte to 10 M/b
- API stable version 0.1.0
- Coverage analysis (coveralls ?)
