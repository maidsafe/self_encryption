# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

*When editing this file, please respect a line length of 100.*

## [0.34.1] - 2025-09-09

### Fixed
- random streaming decryption handling different MAX_CHUNK_SIZE scheme.

## [0.34.0] - 2025-09-05

### Added
- Easy-to-use streaming functions: new `stream_encrypt` and `streaming_decrypt` functions provide 
  simplified APIs for streaming encryption/decryption without requiring manual stream management.
- In-memory streaming encryption: streaming encryption now operates entirely in memory, 
  eliminating disk I/O dependencies for better performance.
- Random access streaming decryption: added random access functionality for streaming decryption,
  enabling flexible data retrieval patterns.

### Changed
- Streaming API improvements: greatly enhanced streaming functionality with better memory 
  management and performance optimizations.
- Code organization: consolidated streaming functionality and removed legacy streaming code for 
  better maintainability.

### Removed
- Legacy streaming implementation: removed outdated stream_old code as part of codebase cleanup.

## [0.33.0] - 2025-08-12

### Fixed
- Streaming decryption: resolved issue where `streaming_decrypt_from_storage` resulted in 
  repeated content due to file append behavior.
- Streaming decryption: corrected streaming behavior to properly process chunks in ordered 
  batches for memory-efficient decryption.

### Changed
- Parallel chunk retrieval function signature: `streaming_decrypt_from_storage` now expects
  chunk retrieval functions to accept and return index-hash tuples `(usize, XorName)` instead
  of just hashes, enabling proper ordering during batch processing [BREAKING].

## [0.32.0] - 2025-08-05

### Added
- Node.js bindings: complete Node.js binding implementation with TypeScript definitions.
- Streaming encrypt for Node.js: added streaming encryption functionality for Node.js bindings.
- XorName utilities for Node.js: added `XorName::to_hex` method and native type support.
- Chunk verification for Node.js: added `verify_chunk` function for Node.js bindings.
- Constants export for Node.js: export MIN_CHUNK_SIZE, MAX_CHUNK_SIZE, and other constants.
- DataMap backward compatibility: added support for deserializing old DataMap format while 
  maintaining new struct format with comprehensive fallback support.
- Enhanced testing: added extensive tests for DataMap backward compatibility scenarios.
- Semi-automated release workflow: new human-reviewed release process with manual triggering.

### Changed
- DataMap binary format: now includes version byte for future compatibility [BREAKING].
- MAX_CHUNK_SIZE constant: changed from lazy_static to proper const [BREAKING].
- Node.js API improvements: more native argument handling and better type integration.
- Python bindings: return `Bytes` instead of `List` for better performance.
- Dependencies: removed unused dependencies (num_cpus, tiny_keccak, lazy_static).
- CI/CD improvements: renamed pr.yml to merge.yml, removed commit linting and cargo fmt 
  constraints, added comprehensive Node.js workflows.
- Code quality: fixed 13 clippy format string warnings, applied rustfmt formatting.

### Fixed
- Python bindings: resolved clippy format string warnings in Python bindings.
- Documentation: removed Python examples using nonexistent functions.
- Build system: properly defined pyo3 as optional dependency.
- CI workflows: fixed Node.js CI workflows and NPM package publishing.

### Removed
- Automated workflows: removed automated version bumping and changelog generation workflows.
- Dependencies: removed unused num_cpus, tiny_keccak, and lazy_static dependencies.
- Legacy code: cleaned up old automated changelog entries.
- PR constraints: removed PR size limit check and commit linting requirements.
