#[no_std]
use serde_json::json;
use alloc::string::{String, ToString};

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
        let message = format!($($arg)*);
        let js = slog::get_json_string(&message, true);
        $serial.write_str(&js).expect("Failed to write log message");
    };

    ($serial:expr, $str:expr) => {
        let serial : Serial<io::InstrIoAccess> = $serial;
        let _str : &str = $str;
        serial.write_str(_str);
    };
}