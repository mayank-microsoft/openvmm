#[no_std]
use serde_json::json;
use alloc::string::{String, ToString};
use crate::sync::Mutex;
use crate::arch::serial::{InstrIoAccess, Serial};

pub enum Level {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4,

}

pub fn get_json_string(s: &String, terminate_new_line: bool, level: Level) -> String {
    let out = json!({
        "type:": "log",
        "message": s,
        "level": match level {
            Level::DEBUG => "DEBUG",
            Level::INFO => "INFO",
            Level::WARNING => "WARNING",
            Level::ERROR => "ERROR",
            Level::CRITICAL => "CRITICAL",
        },
    });
    let mut out = out.to_string();
    if terminate_new_line {
        out.push('\n');
    }
    return out;
}

pub fn get_json_test_assertion_string(s: &str, terminate_new_line: bool, line: String, assert_result: bool) -> String {
    let out = json!({
        "type:": "assertion",
        "message": s,
        "level": "CRITICAL",
        "line": line,
        "assertion_result": assert_result,
    });
    let mut out = out.to_string();
    if terminate_new_line {
        out.push('\n');
    }
    return out;
}

pub static mut SERIAL: Serial<InstrIoAccess> = Serial::new(InstrIoAccess {});

#[macro_export]
macro_rules! tmk_assert {
    ($condition:expr) => {
        let file = core::file!();
        let line = line!();
        let file_line = format!("{}:{}", file, line);
        let expn = stringify!($condition);
        let result: bool = $condition;
        let js = crate::slog::get_json_test_assertion_string(&expn, true, file_line , result);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}
#[macro_export]
macro_rules! logt {
    ($($arg:tt)*) => {
        {
        use core::fmt::Write;
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::INFO);
        unsafe { crate::slog::SERIAL.write_str(&js) };
        }
    };
}

#[macro_export]
macro_rules! errorlog {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::ERROR);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}

#[macro_export]
macro_rules! debuglog {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::DEBUG);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}

#[macro_export]
macro_rules! infolog {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::INFO);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}

#[macro_export]
macro_rules! warninglog {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::WARNING);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}

#[macro_export]
macro_rules! criticallog {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let js = crate::slog::get_json_string(&message, true, crate::slog::Level::CRITICAL);
        unsafe { crate::slog::SERIAL.write_str(&js) };
    };
}


#[macro_export]
macro_rules! slog {

    ($serial:expr, $($arg:tt)*) => {
        let mut serial : &mut Mutex<Serial<InstrIoAccess>> = &mut $serial;
        let message = format!($($arg)*);
        let js = slog::get_json_string(&message, true, crate::slog::Level::INFO);
        {
            let mut serial = serial.lock();
            serial.get_mut().write_str(&js);
        }
    };

}

