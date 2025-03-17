#[no_std]
use serde_json::json;
use alloc::string::{String, ToString};
use crate::sync::Mutex;
use crate::arch::serial::Serial;

pub fn get_json_string(s: &String, terminate_new_line: bool) -> String {
    let out = json!({
        "message": s,
    });
    let mut out = out.to_string();
    if terminate_new_line {
        out.push('\n');
    }
    return out;
}

#[macro_export]
macro_rules! slog {

    ($serial:expr, $($arg:tt)*) => {
        let mut serial : &mut Mutex<Serial<InstrIoAccess>> = &mut $serial;
        let message = format!($($arg)*);
        let js = slog::get_json_string(&message, true);
        {
            let mut serial = serial.lock();
            serial.get_mut().write_str(&js);
        }
    };

}