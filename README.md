# self_encryption

**Self encrypting files (convergent encryption plus obfuscation)**


Travis build and test status

[![Build Status](https://travis-ci.org/dirvine/self_encryption.svg?branch=master)](https://travis-ci.org/dirvine/self_encryption)

Windows build status

[![Build
status](https://ci.appveyor.com/api/projects/status/qveqoe45n56atlk7?svg=true)](https://ci.appveyor.com/project/dirvine/self-encryption)

[Documentation](http://dirvine.github.io/self_encryption/self_encryption/)

[MaidSafe System Documention](http://systemdocs.maidsafe.net/)

[MaidSafe web site](http:://www.maidsafe.net)

[MaidSafe Community site](http:://www.maidsafe.org)

![image of self encryption] (https://github.com/dirvine/self_encryption/blob/master/img/self-encryption.png?raw=true)

## ToDo list

- [x] Initial structure
- [x] Test set-up
- [x] Travis integration
- [x] Docs creation
- [x] Docs hosting (github.io)
- [ ] Windows CI set-up (ci.AppVeyor.com)
- [ ] API stable version 1.0
- [ ] Read/Write file in memory based buffer
- [ ] Allow any size file
    - [ ] Replace sequencer with new struct and use BufferedStream to offload to disk
    - [ ] Clean up any cache chunks when disk space is low (start + now < 90%)
    - [ ] Store intermediate chunks when disk space is low (start + now < 90%)
- [ ] Add another functor to constructor to allow storage query for chunks (not get)
- [ ] Check for first last middle chunks on net and presume file stored
- [ ] Coverage analysis (coveralls ?)
