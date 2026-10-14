//! Minimal terminal queries for the start screen: the window size and, on
//! Windows, enabling ANSI escape processing for older consoles. Standard
//! library APIs do not expose these, and a crate would be a new dependency for
//! two system calls.

/// Visible terminal size as (columns, rows), when stdout is a terminal.
pub(crate) fn size() -> Option<(usize, usize)> {
    platform::size().or_else(|| {
        let columns = std::env::var("COLUMNS").ok()?.parse().ok()?;
        let rows = std::env::var("LINES").ok()?.parse().ok()?;
        Some((columns, rows))
    })
}

/// Makes the console interpret ANSI sequences; returns whether it does.
pub(crate) fn enable_ansi() -> bool {
    platform::enable_ansi()
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    const STD_OUTPUT_HANDLE: u32 = -11_i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    #[repr(C)]
    #[derive(Default)]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    #[derive(Default)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ScreenBufferInfo {
        size: Coord,
        cursor_position: Coord,
        attributes: u16,
        window: SmallRect,
        maximum_window_size: Coord,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(handle: u32) -> *mut c_void;
        fn GetConsoleScreenBufferInfo(console: *mut c_void, info: *mut ScreenBufferInfo) -> i32;
        fn GetConsoleMode(console: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(console: *mut c_void, mode: u32) -> i32;
    }

    fn output() -> Option<*mut c_void> {
        // SAFETY: GetStdHandle has no preconditions and returns a handle or null/-1.
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        (!handle.is_null() && handle as isize != -1).then_some(handle)
    }

    pub(super) fn size() -> Option<(usize, usize)> {
        let handle = output()?;
        let mut info = ScreenBufferInfo::default();
        // SAFETY: `info` is a valid, writable CONSOLE_SCREEN_BUFFER_INFO.
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
            return None;
        }
        let columns = i32::from(info.window.right) - i32::from(info.window.left) + 1;
        let rows = i32::from(info.window.bottom) - i32::from(info.window.top) + 1;
        Some((usize::try_from(columns).ok()?, usize::try_from(rows).ok()?))
    }

    pub(super) fn enable_ansi() -> bool {
        let Some(handle) = output() else {
            return false;
        };
        let mut mode = 0;
        // SAFETY: `mode` is a valid, writable u32 for the console mode.
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        // SAFETY: only adds a documented flag to the mode read above.
        unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 }
    }
}

#[cfg(unix)]
mod platform {
    #[repr(C)]
    #[derive(Default)]
    struct WindowSize {
        rows: u16,
        columns: u16,
        x_pixels: u16,
        y_pixels: u16,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TIOCGWINSZ: std::ffi::c_ulong = 0x5413;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const TIOCGWINSZ: std::ffi::c_ulong = 0x4008_7468;

    unsafe extern "C" {
        fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
    }

    pub(super) fn size() -> Option<(usize, usize)> {
        let mut size = WindowSize::default();
        // SAFETY: TIOCGWINSZ writes one `struct winsize` to the valid pointer.
        if unsafe { ioctl(1, TIOCGWINSZ, &mut size as *mut WindowSize) } != 0 {
            return None;
        }
        (size.columns > 0 && size.rows > 0)
            .then(|| (usize::from(size.columns), usize::from(size.rows)))
    }

    pub(super) fn enable_ansi() -> bool {
        true
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    pub(super) fn size() -> Option<(usize, usize)> {
        None
    }

    pub(super) fn enable_ansi() -> bool {
        false
    }
}
