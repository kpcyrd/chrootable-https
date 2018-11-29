#[cfg(unix)]
#[path = "unix.rs"]
mod os;

#[cfg(windows)]
#[path = "windows.rs"]
mod os;

pub use self::os::read_system_conf;
