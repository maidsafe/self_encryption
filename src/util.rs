// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use futures::Future;

// Type alias for Box<Future>. Unlike `futures::BoxFuture` this doesn't require
// the future to implement `Send`.
pub type BoxFuture<T, E> = Box<Future<Item = T, Error = E>>;

// Extension methods for Future.
pub trait FutureExt: Future {
    fn into_box(self) -> BoxFuture<Self::Item, Self::Error>;
}

impl<F> FutureExt for F
where
    F: Future + 'static,
{
    fn into_box(self) -> BoxFuture<Self::Item, Self::Error> {
        Box::new(self)
    }
}
