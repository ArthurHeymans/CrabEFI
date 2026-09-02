//! EFI Graphics Output Protocol (GOP)
//!
//! This module implements the UEFI Graphics Output Protocol, which provides
//! framebuffer access to the OS. We expose the framebuffer information from
//! coreboot tables.

use r_efi::efi::Status;
use r_efi::protocols::graphics_output;

use crate::efi::allocator::{MemoryType, allocate_pool};
use crate::efi::utils::allocate_protocol_with_log;
use crate::platform::FramebufferConfig;
use crate::state;

/// Graphics Output Protocol GUID supplied by `r-efi`.
pub const GRAPHICS_OUTPUT_GUID: r_efi::efi::Guid = graphics_output::PROTOCOL_GUID;

/// Pixel format ABI supplied by `r-efi`.
pub type PixelFormat = graphics_output::GraphicsPixelFormat;
/// Pixel bitmask ABI supplied by `r-efi`.
pub type PixelBitmask = graphics_output::PixelBitmask;
/// GOP mode information ABI supplied by `r-efi`.
pub type GopModeInfo = graphics_output::ModeInformation;
/// GOP mode ABI supplied by `r-efi`.
pub type GopMode = graphics_output::Mode;
/// BLT operation ABI supplied by `r-efi`.
pub type BltOperation = graphics_output::BltOperation;
/// BLT pixel ABI supplied by `r-efi`.
pub type BltPixel = graphics_output::BltPixel;
/// Graphics Output Protocol ABI supplied by `r-efi`.
pub type GraphicsOutputProtocol = graphics_output::Protocol;

/// Query available video mode information
extern "efiapi" fn gop_query_mode(
    this: *mut GraphicsOutputProtocol,
    mode_number: u32,
    size_of_info: *mut usize,
    info: *mut *mut GopModeInfo,
) -> Status {
    log::debug!(
        "GOP.QueryMode(mode_number={}, size_of_info={:?}, info={:?})",
        mode_number,
        size_of_info,
        info
    );

    if this.is_null() || size_of_info.is_null() || info.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // We only support mode 0
    if mode_number != 0 {
        return Status::INVALID_PARAMETER;
    }

    let protocol = unsafe { &*this };
    if protocol.mode.is_null() {
        return Status::DEVICE_ERROR;
    }

    let mode = unsafe { &*protocol.mode };

    // Allocate memory for the mode info copy
    let info_size = core::mem::size_of::<GopModeInfo>();
    let info_ptr = match allocate_pool(MemoryType::BootServicesData, info_size) {
        Ok(p) => p as *mut GopModeInfo,
        Err(_) => return Status::OUT_OF_RESOURCES,
    };

    // Copy mode info
    unsafe {
        core::ptr::copy_nonoverlapping(mode.info, info_ptr, 1);
        *size_of_info = info_size;
        *info = info_ptr;
    }

    log::debug!("  -> SUCCESS (info at {:?})", info_ptr);
    Status::SUCCESS
}

/// Set video mode
extern "efiapi" fn gop_set_mode(this: *mut GraphicsOutputProtocol, mode_number: u32) -> Status {
    log::debug!("GOP.SetMode(mode_number={})", mode_number);

    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // We only support mode 0 (the current mode from coreboot)
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }

    // Mode 0 is already set
    log::debug!("  -> SUCCESS (mode already set)");
    Status::SUCCESS
}

/// Block transfer (Blt) operation
extern "efiapi" fn gop_blt(
    this: *mut GraphicsOutputProtocol,
    blt_buffer: *mut BltPixel,
    blt_operation: BltOperation,
    source_x: usize,
    source_y: usize,
    destination_x: usize,
    destination_y: usize,
    width: usize,
    height: usize,
    delta: usize,
) -> Status {
    log::trace!(
        "GOP.Blt(op={:?}, src=({},{}), dst=({},{}), size={}x{}, delta={})",
        blt_operation,
        source_x,
        source_y,
        destination_x,
        destination_y,
        width,
        height,
        delta
    );

    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let console = unsafe { &*state::console_ptr() };
    let fb = match console.gop_framebuffer.as_ref() {
        Some(fb) => fb,
        None => return Status::DEVICE_ERROR,
    };
    let fb_width = fb.width as usize;
    let fb_height = fb.height as usize;
    let fb_ptr = fb.physical_address as *mut u8;

    // Calculate buffer line length
    let buffer_line_length = if delta != 0 {
        delta / core::mem::size_of::<BltPixel>()
    } else {
        width
    };

    match blt_operation {
        graphics_output::BLT_VIDEO_FILL => {
            // Fill a rectangle with a single color
            if blt_buffer.is_null() {
                return Status::INVALID_PARAMETER;
            }

            if destination_x + width > fb_width || destination_y + height > fb_height {
                return Status::INVALID_PARAMETER;
            }

            let pixel = unsafe { *blt_buffer };

            for y in 0..height {
                for x in 0..width {
                    let fb_x = destination_x + x;
                    let fb_y = destination_y + y;
                    unsafe {
                        write_pixel_to_fb(fb, fb_ptr, fb_x, fb_y, &pixel);
                    }
                }
            }
        }

        graphics_output::BLT_VIDEO_TO_BLT_BUFFER => {
            // Copy from video memory to buffer
            if blt_buffer.is_null() {
                return Status::INVALID_PARAMETER;
            }

            if source_x + width > fb_width || source_y + height > fb_height {
                return Status::INVALID_PARAMETER;
            }

            for y in 0..height {
                for x in 0..width {
                    let fb_x = source_x + x;
                    let fb_y = source_y + y;
                    let buf_idx = (destination_y + y) * buffer_line_length + (destination_x + x);

                    unsafe {
                        let pixel = read_pixel_from_fb(fb, fb_ptr, fb_x, fb_y);
                        *blt_buffer.add(buf_idx) = pixel;
                    }
                }
            }
        }

        graphics_output::BLT_BUFFER_TO_VIDEO => {
            // Copy from buffer to video memory
            if blt_buffer.is_null() {
                return Status::INVALID_PARAMETER;
            }

            if destination_x + width > fb_width || destination_y + height > fb_height {
                return Status::INVALID_PARAMETER;
            }

            for y in 0..height {
                for x in 0..width {
                    let buf_idx = (source_y + y) * buffer_line_length + (source_x + x);
                    let fb_x = destination_x + x;
                    let fb_y = destination_y + y;

                    unsafe {
                        let pixel = *blt_buffer.add(buf_idx);
                        write_pixel_to_fb(fb, fb_ptr, fb_x, fb_y, &pixel);
                    }
                }
            }
        }

        graphics_output::BLT_VIDEO_TO_VIDEO => {
            // Copy within video memory
            if source_x + width > fb_width || source_y + height > fb_height {
                return Status::INVALID_PARAMETER;
            }
            if destination_x + width > fb_width || destination_y + height > fb_height {
                return Status::INVALID_PARAMETER;
            }

            // Handle overlapping regions by choosing copy direction
            let copy_forward = destination_y < source_y
                || (destination_y == source_y && destination_x <= source_x);

            if copy_forward {
                for y in 0..height {
                    for x in 0..width {
                        unsafe {
                            let pixel = read_pixel_from_fb(fb, fb_ptr, source_x + x, source_y + y);
                            write_pixel_to_fb(
                                fb,
                                fb_ptr,
                                destination_x + x,
                                destination_y + y,
                                &pixel,
                            );
                        }
                    }
                }
            } else {
                for y in (0..height).rev() {
                    for x in (0..width).rev() {
                        unsafe {
                            let pixel = read_pixel_from_fb(fb, fb_ptr, source_x + x, source_y + y);
                            write_pixel_to_fb(
                                fb,
                                fb_ptr,
                                destination_x + x,
                                destination_y + y,
                                &pixel,
                            );
                        }
                    }
                }
            }
        }
        _ => return Status::INVALID_PARAMETER,
    }

    Status::SUCCESS
}

/// Write a BltPixel to framebuffer at (x, y)
unsafe fn write_pixel_to_fb(
    fb: &FramebufferConfig,
    fb_ptr: *mut u8,
    x: usize,
    y: usize,
    pixel: &BltPixel,
) {
    unsafe {
        let bytes_per_pixel = (fb.bits_per_pixel / 8) as usize;
        let offset = y * fb.bytes_per_line() as usize + x * bytes_per_pixel;
        let ptr = fb_ptr.add(offset);

        match fb.bits_per_pixel {
            32 => {
                // Encode based on mask positions
                let value = ((pixel.red as u32) << fb.red_mask_pos)
                    | ((pixel.green as u32) << fb.green_mask_pos)
                    | ((pixel.blue as u32) << fb.blue_mask_pos);
                (ptr as *mut u32).write_volatile(value);
            }
            24 => {
                if fb.blue_mask_pos < fb.red_mask_pos {
                    // BGR
                    ptr.write_volatile(pixel.blue);
                    ptr.add(1).write_volatile(pixel.green);
                    ptr.add(2).write_volatile(pixel.red);
                } else {
                    // RGB
                    ptr.write_volatile(pixel.red);
                    ptr.add(1).write_volatile(pixel.green);
                    ptr.add(2).write_volatile(pixel.blue);
                }
            }
            16 => {
                // RGB565 typically
                let r = (pixel.red >> 3) as u16;
                let g = (pixel.green >> 2) as u16;
                let b = (pixel.blue >> 3) as u16;
                let value = (r << 11) | (g << 5) | b;
                (ptr as *mut u16).write_volatile(value);
            }
            _ => {}
        }
    }
}

/// Read a BltPixel from framebuffer at (x, y)
unsafe fn read_pixel_from_fb(
    fb: &FramebufferConfig,
    fb_ptr: *mut u8,
    x: usize,
    y: usize,
) -> BltPixel {
    unsafe {
        let bytes_per_pixel = (fb.bits_per_pixel / 8) as usize;
        let offset = y * fb.bytes_per_line() as usize + x * bytes_per_pixel;
        let ptr = fb_ptr.add(offset);

        match fb.bits_per_pixel {
            32 => {
                let value = (ptr as *const u32).read_volatile();
                BltPixel {
                    red: ((value >> fb.red_mask_pos) & 0xFF) as u8,
                    green: ((value >> fb.green_mask_pos) & 0xFF) as u8,
                    blue: ((value >> fb.blue_mask_pos) & 0xFF) as u8,
                    reserved: 0,
                }
            }
            24 => {
                if fb.blue_mask_pos < fb.red_mask_pos {
                    // BGR
                    BltPixel {
                        blue: ptr.read_volatile(),
                        green: ptr.add(1).read_volatile(),
                        red: ptr.add(2).read_volatile(),
                        reserved: 0,
                    }
                } else {
                    // RGB
                    BltPixel {
                        red: ptr.read_volatile(),
                        green: ptr.add(1).read_volatile(),
                        blue: ptr.add(2).read_volatile(),
                        reserved: 0,
                    }
                }
            }
            16 => {
                let value = (ptr as *const u16).read_volatile();
                BltPixel {
                    red: ((value >> 11) << 3) as u8,
                    green: (((value >> 5) & 0x3F) << 2) as u8,
                    blue: ((value & 0x1F) << 3) as u8,
                    reserved: 0,
                }
            }
            _ => BltPixel {
                blue: 0,
                green: 0,
                red: 0,
                reserved: 0,
            },
        }
    }
}

/// Create the Graphics Output Protocol from framebuffer configuration
///
/// # Returns
/// A pointer to the GraphicsOutputProtocol, or null on failure
pub fn create_gop(framebuffer: &FramebufferConfig) -> *mut GraphicsOutputProtocol {
    // Determine pixel format based on mask positions
    let (pixel_format, pixel_bitmask) = if framebuffer.bits_per_pixel == 32 {
        if framebuffer.red_mask_pos == 16
            && framebuffer.green_mask_pos == 8
            && framebuffer.blue_mask_pos == 0
        {
            // BGRA (most common)
            (
                graphics_output::PIXEL_BLUE_GREEN_RED_RESERVED_8_BIT_PER_COLOR,
                PixelBitmask {
                    red_mask: 0,
                    green_mask: 0,
                    blue_mask: 0,
                    reserved_mask: 0,
                },
            )
        } else if framebuffer.red_mask_pos == 0
            && framebuffer.green_mask_pos == 8
            && framebuffer.blue_mask_pos == 16
        {
            // RGBA
            (
                graphics_output::PIXEL_RED_GREEN_BLUE_RESERVED_8_BIT_PER_COLOR,
                PixelBitmask {
                    red_mask: 0,
                    green_mask: 0,
                    blue_mask: 0,
                    reserved_mask: 0,
                },
            )
        } else {
            // Custom bitmask
            let bitmask = PixelBitmask {
                red_mask: 0xFF << framebuffer.red_mask_pos,
                green_mask: 0xFF << framebuffer.green_mask_pos,
                blue_mask: 0xFF << framebuffer.blue_mask_pos,
                reserved_mask: 0,
            };
            (graphics_output::PIXEL_BIT_MASK, bitmask)
        }
    } else {
        // For non-32bpp, use bitmask
        let bitmask = PixelBitmask {
            red_mask: ((1u32 << framebuffer.red_mask_size) - 1) << framebuffer.red_mask_pos,
            green_mask: ((1u32 << framebuffer.green_mask_size) - 1) << framebuffer.green_mask_pos,
            blue_mask: ((1u32 << framebuffer.blue_mask_size) - 1) << framebuffer.blue_mask_pos,
            reserved_mask: 0,
        };
        (graphics_output::PIXEL_BIT_MASK, bitmask)
    };

    // Allocate mode info
    let mode_info_ptr = allocate_protocol_with_log::<GopModeInfo>("GopModeInfo", |m| {
        m.version = 0;
        m.horizontal_resolution = framebuffer.width;
        m.vertical_resolution = framebuffer.height;
        m.pixel_format = pixel_format;
        m.pixel_information = pixel_bitmask;
        m.pixels_per_scan_line = framebuffer.stride;
    });
    if mode_info_ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Allocate GOP mode structure
    let mode_ptr = allocate_protocol_with_log::<GopMode>("GopMode", |m| {
        m.max_mode = 1; // We support 1 mode (mode 0)
        m.mode = 0;
        m.info = mode_info_ptr;
        m.size_of_info = core::mem::size_of::<GopModeInfo>();
        m.frame_buffer_base = framebuffer.physical_address;
        m.frame_buffer_size = framebuffer.size() as usize;
    });
    if mode_ptr.is_null() {
        crate::efi::allocator::free_pool(mode_info_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    // Allocate protocol structure
    let protocol_ptr =
        allocate_protocol_with_log::<GraphicsOutputProtocol>("GraphicsOutputProtocol", |p| {
            p.query_mode = gop_query_mode;
            p.set_mode = gop_set_mode;
            p.blt = gop_blt;
            p.mode = mode_ptr;
        });
    if protocol_ptr.is_null() {
        crate::efi::allocator::free_pool(mode_info_ptr as *mut u8);
        crate::efi::allocator::free_pool(mode_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    // Store global state for Blt operations
    state::with_console_mut(|console| {
        console.gop_framebuffer = Some(*framebuffer);
    });

    log::info!(
        "GraphicsOutputProtocol created: {}x{} @ {:#x}, {:?}",
        framebuffer.width,
        framebuffer.height,
        framebuffer.physical_address,
        pixel_format
    );

    protocol_ptr
}
