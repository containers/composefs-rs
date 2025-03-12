#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        println!("{}:{}: {}", file!(), line!(), format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! etrace {
    ($($arg:tt)*) => {
        eprintln!("{}:{}: {}", file!(), line!(), format_args!($($arg)*));
    };
}
