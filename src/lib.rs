#![no_std]
#![deny(unused_crate_dependencies)]

pub mod cut_metadata;
pub mod error;
#[cfg(test)]
mod tests;
pub mod traits;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc as std;
