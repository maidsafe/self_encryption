// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

//! Implementation of a single use-case for Self-Encryption

extern crate self_encryption;

fn usage() {
	println!("Usage: self-encrypt or decrypt a file");
    println!("Usage: se [-e|-d] <source> <output>");
}

fn main() {

	let args = std::os::args();
    let mut args = args.iter().map(|arg| &arg[..]);

    enum Mode {
      Encrypt,
      Decrypt
    }

    // Skip program name
    args.next();

    let mode = match arg.next() {
      Some("-e") => Mode::Encrypt,
      Some("-d") => Mode::Decrypt,
      _ => { usage(); return;}
    }

    let files = match &args.collect::<Vec<_>>()[..] {
    	
    }
}