#[cfg(feature = "statistics")]
mod imple;
#[cfg(not(feature = "statistics"))]
mod unimpl;

#[cfg(feature = "statistics")]
pub use self::imple::*;
#[cfg(not(feature = "statistics"))]
pub use self::unimpl::*;
