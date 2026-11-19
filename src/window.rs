use crate::preview::{HEIGHT, WIDTH};
use std::cell::RefCell;
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;

type Handle = *mut c_void;
type WindowProc = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000f;
const WM_KEYDOWN: u32 = 0x0100;
const VK_ESCAPE: usize = 0x1b;
const WS_OVERLAPPEDWINDOW: u32 = 0x00cf_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const CW_USEDEFAULT: i32 = i32::MIN;
const IDC_ARROW: *const u16 = 32512 as *const u16;
const BLACK_BRUSH: i32 = 4;
const SRCCOPY: u32 = 0x00cc_0020;

#[repr(C)]
struct WindowClass {
    style: u32,
    procedure: WindowProc,
    class_extra: i32,
    window_extra: i32,
    instance: Handle,
    icon: Handle,
    cursor: Handle,
    background: Handle,
    menu_name: *const u16,
    class_name: *const u16,
}

#[derive(Default)]
#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct Message {
    window: Handle,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    point: [i32; 2],
    private: u32,
}

#[repr(C)]
struct Paint {
    context: Handle,
    erase: i32,
    rect: Rect,
    restore: i32,
    incremental_update: i32,
    reserved: [u8; 32],
}

#[repr(C)]
struct BitmapInfo {
    size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bits_per_pixel: u16,
    compression: u32,
    image_size: u32,
    x_pixels_per_meter: i32,
    y_pixels_per_meter: i32,
    colors_used: u32,
    colors_important: u32,
    palette: [u8; 4],
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Handle;
}

#[link(name = "user32")]
extern "system" {
    fn LoadCursorW(instance: Handle, name: *const u16) -> Handle;
    fn RegisterClassW(class: *const WindowClass) -> u16;
    fn UnregisterClassW(class: *const u16, instance: Handle) -> i32;
    fn CreateWindowExW(
        extended_style: u32,
        class: *const u16,
        title: *const u16,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: Handle,
        menu: Handle,
        instance: Handle,
        param: *mut c_void,
    ) -> Handle;
    fn DestroyWindow(window: Handle) -> i32;
    fn DefWindowProcW(window: Handle, message: u32, wparam: usize, lparam: isize) -> isize;
    fn PostQuitMessage(code: i32);
    fn GetMessageW(message: *mut Message, window: Handle, min: u32, max: u32) -> i32;
    fn TranslateMessage(message: *const Message) -> i32;
    fn DispatchMessageW(message: *const Message) -> isize;
    fn GetClientRect(window: Handle, rect: *mut Rect) -> i32;
    fn BeginPaint(window: Handle, paint: *mut Paint) -> Handle;
    fn EndPaint(window: Handle, paint: *const Paint) -> i32;
}

#[link(name = "gdi32")]
extern "system" {
    fn GetStockObject(index: i32) -> Handle;
    fn StretchDIBits(
        context: Handle,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        src_x: i32,
        src_y: i32,
        src_width: i32,
        src_height: i32,
        bits: *const u8,
        info: *const BitmapInfo,
        usage: u32,
        raster_operation: u32,
    ) -> i32;
}

thread_local! {
    static PIXELS: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

pub fn show(pixels: Vec<u8>) -> io::Result<()> {
    PIXELS.replace(Some(pixels));
    // This thread owns the window, the pixel data, and the message queue.
    let result = unsafe { open_window() };
    PIXELS.take();
    result
}

unsafe fn open_window() -> io::Result<()> {
    let class: Vec<u16> = "WarframeU51Preview\0".encode_utf16().collect();
    let title: Vec<u16> = "Warframe U5.1 - SigninReward texture\0"
        .encode_utf16()
        .collect();
    let instance = GetModuleHandleW(std::ptr::null());
    if instance.is_null() {
        return Err(io::Error::last_os_error());
    }
    if RegisterClassW(&WindowClass {
        style: 3, // Redraw the client area on horizontal or vertical resize.
        procedure: window_proc,
        class_extra: 0,
        window_extra: 0,
        instance,
        icon: null_mut(),
        cursor: LoadCursorW(null_mut(), IDC_ARROW),
        background: GetStockObject(BLACK_BRUSH),
        menu_name: std::ptr::null(),
        class_name: class.as_ptr(),
    }) == 0
    {
        return Err(io::Error::last_os_error());
    }
    let window = CreateWindowExW(
        0,
        class.as_ptr(),
        title.as_ptr(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        680,
        300,
        null_mut(),
        null_mut(),
        instance,
        null_mut(),
    );
    let result = if window.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // MSG can be zero-initialized before GetMessageW fills it.
        let mut message: Message = std::mem::zeroed();
        loop {
            match GetMessageW(&mut message, null_mut(), 0, 0) {
                0 => break Ok(()),
                -1 => {
                    let error = io::Error::last_os_error();
                    DestroyWindow(window);
                    break Err(error);
                }
                _ => {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        }
    };
    UnregisterClassW(class.as_ptr(), instance);
    result
}

unsafe extern "system" fn window_proc(
    window: Handle,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match message {
        WM_PAINT => paint_preview(window),
        WM_DESTROY => PostQuitMessage(0),
        WM_KEYDOWN if wparam == VK_ESCAPE => {
            DestroyWindow(window);
        }
        _ => return DefWindowProcW(window, message, wparam, lparam),
    }
    0
}

unsafe fn paint_preview(window: Handle) {
    // PAINTSTRUCT can be zero-initialized before BeginPaint fills it.
    let mut paint: Paint = std::mem::zeroed();
    let context = BeginPaint(window, &mut paint);
    if context.is_null() {
        return;
    }
    let mut rect = Rect::default();
    if GetClientRect(window, &mut rect) != 0 {
        PIXELS.with(|slot| {
            let pixels = slot.borrow();
            if let Some(pixels) = pixels.as_ref() {
                let scale = (rect.right / WIDTH).min(rect.bottom / HEIGHT).max(1);
                let (width, height) = (WIDTH * scale, HEIGHT * scale);
                let bitmap = BitmapInfo {
                    size: 40,
                    width: WIDTH,
                    height: -HEIGHT, // Top-down DIB rows match the cache texture.
                    planes: 1,
                    bits_per_pixel: 32,
                    compression: 0, // BI_RGB
                    image_size: 0,
                    x_pixels_per_meter: 0,
                    y_pixels_per_meter: 0,
                    colors_used: 0,
                    colors_important: 0,
                    palette: [0; 4],
                };
                StretchDIBits(
                    context,
                    (rect.right - width) / 2,
                    (rect.bottom - height) / 2,
                    width,
                    height,
                    0,
                    0,
                    WIDTH,
                    HEIGHT,
                    pixels.as_ptr(),
                    &bitmap,
                    0,
                    SRCCOPY,
                );
            }
        });
    }
    EndPaint(window, &paint);
}
