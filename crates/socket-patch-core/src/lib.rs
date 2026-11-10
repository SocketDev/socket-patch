// The four print macros, crate-wide: every call site in the modules below
// goes through `utils::stdio::print`, so a closed stdout or stderr pipe
// stops the printing instead of panicking mid-run once the binary has
// opted in (see `utils::stdio`). Declared before the modules: a
// `macro_rules!` shadows std's macro only in what follows it. All four are
// defined whether or not core prints with each today, so the next call
// site cannot slip past.
#[allow(unused_macros)]
macro_rules! println {
    () => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stdout, true, ::std::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stdout, true, ::std::format_args!($($arg)*))
    };
}
#[allow(unused_macros)]
macro_rules! eprintln {
    () => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stderr, true, ::std::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stderr, true, ::std::format_args!($($arg)*))
    };
}
#[allow(unused_macros)]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stdout, false, ::std::format_args!($($arg)*))
    };
}
#[allow(unused_macros)]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::utils::stdio::print($crate::utils::stdio::Stream::Stderr, false, ::std::format_args!($($arg)*))
    };
}

pub mod api;
pub mod constants;
pub mod crawlers;
pub mod formats;
pub mod gradle;
pub mod hash;
pub mod hosted;
pub mod ledgers;
pub mod manifest;
pub mod origin;
pub mod patch;
pub mod policy;
pub mod rollout;
pub mod telemetry;
pub mod update;
pub mod utils;
pub mod vendor;
pub mod vex;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_env_tests;
#[cfg(test)]
mod test_rng;
