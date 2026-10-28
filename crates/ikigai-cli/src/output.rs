//! Terminal stdout writes: a consumer closing its pipe is a normal end of output.

use std::fmt;
use std::io::{self, Write};

/// Flush each write so a buffered failure is handled here, including short output
/// without a newline. Stop immediately rather than evaluating more commands or
/// waiting for another REPL input after the consumer has gone away.
pub(crate) fn write(args: fmt::Arguments<'_>) {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if let Err(error) = stdout.write_fmt(args).and_then(|()| stdout.flush()) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        let _ = writeln!(
            io::stderr().lock(),
            "ikigai: could not write stdout: {error}"
        );
        std::process::exit(1);
    }
}

macro_rules! print {
    ($($arg:tt)*) => {
        $crate::output::write(format_args!($($arg)*))
    };
}

macro_rules! println {
    () => { $crate::output::write(format_args!("\n")) };
    ($($arg:tt)*) => {
        $crate::output::write(format_args!("{}\n", format_args!($($arg)*)))
    };
}

pub(crate) use {print, println};
