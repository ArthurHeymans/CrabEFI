//! EFI Graphics Output Protocol (GOP)
//!
//! This module implements the UEFI Graphics Output Protocol, which provides
//! framebuffer access to the OS. We expose the framebuffer information from
//! coreboot tables.

use r_efi::efi::{Guid, Status};

use crate::coreboot::FramebufferInfo;
use crate::efi::allocator::{MemoryType, allocate_pool};
use crate::state;

/// EFI_GRAPHICS_OUTPUT_PROTOCOL GUID
pub const GRAPHICS_OUTPUT_GUID: Guid = Guid::from_fields(
    0x9042a9de,
    0x23dc,
    0x4a38,
    0x96,
    0xfb,
    &[0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);

/// Pixel format enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PixelFormat {
    /// Red-Green-Blue-Reserved 8-bit per color
    RedGreenBlueReserved8BitPerColor = 0,
    /// Blue-Green-Red-Reserved 8-bit per color
    BlueGreenRedReserved8BitPerColor = 1,
    /// Pixel format defined by pixel_bitmask
    BitMask = 2,
    /// Only valid for Blt operations
    BltOnly = 3,
}

/// Pixel bitmask structure for BitMask pixel format
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

/// GOP Mode Information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct GopModeInfo {
    /// Version of the structure (should be 0)
    pub version: u32,
    /// Horizontal resolution in pixels
    pub horizontal_resolution: u32,
    /// Vertical resolution in pixels
    pub vertical_resolution: u32,
    /// Pixel format
    pub pixel_format: PixelFormat,
    /// Pixel bitmask (only valid if pixel_format is BitMask)
    pub pixel_information: PixelBitmask,
    /// Number of pixels per video memory scan line
    pub pixels_per_scan_line: u32,
}

/// GOP Mode structure
#[repr(C)]
pub struct GopMode {
    /// Maximum mode number supported (0-based, so max_mode=1 means mode 0 only)
    pub max_mode: u32,
    /// Current mode number
    pub mode: u32,
    /// Pointer to mode information
    pub info: *mut GopModeInfo,
    /// Size of the mode information structure
    pub size_of_info: usize,
    /// Physical address of the framebuffer
    pub frame_buffer_base: u64,
    /// Size of the framebuffer in bytes
    pub frame_buffer_size: usize,
}

/// BLT (Block Transfer) operation types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BltOperation {
    /// Fill rectangle with color
    VideoFill = 0,
    /// Copy from video to buffer
    VideoToBltBuffer = 1,
    /// Copy from buffer to video
    BufferToVideo = 2,
    /// Copy within video memory
    VideoToVideo = 3,
}

/// BLT pixel structure (BGRA format)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BltPixel {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub reserved: u8,
}

/// Graphics Output Protocol structure
#[repr(C)]
pub struct GraphicsOutputProtocol {
    pub query_mode: extern "efiapi" fn(
        this: *mut GraphicsOutputProtocol,
        mode_number: u32,
        size_of_info: *mut usize,
        info: *mut *mut GopModeInfo,
    ) -> Status,
    pub set_mode: extern "efiapi" fn(this: *mut GraphicsOutputProtocol, mode_number: u32) -> Status,
    pub blt: extern "efiapi" fn(
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
    ) -> Status,
    pub mode: *mut GopMode,
}

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

    let console = state::console();
    let fb = match console.gop_framebuffer.as_ref() {
        Some(fb) => fb,
        None => return Status::DEVICE_ERROR,
    };
    let fb_width = fb.x_resolution as usize;
    let fb_height = fb.y_resolution as usize;
    let fb_ptr = fb.physical_address as *mut u8;

    // Calculate buffer line length
    let buffer_line_length = if delta != 0 {
        delta / core::mem::size_of::<BltPixel>()
    } else {
        width
    };

    match blt_operation {
        BltOperation::VideoFill => {
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

        BltOperation::VideoToBltBuffer => {
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

        BltOperation::BufferToVideo => {
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

        BltOperation::VideoToVideo => {
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
    }

    Status::SUCCESS
}

/// Write a BltPixel to framebuffer at (x, y)
unsafe fn write_pixel_to_fb(
    fb: &FramebufferInfo,
    fb_ptr: *mut u8,
    x: usize,
    y: usize,
    pixel: &BltPixel,
) {
    let bytes_per_pixel = (fb.bits_per_pixel / 8) as usize;
    let offset = y * fb.bytes_per_line as usize + x * bytes_per_pixel;
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

/// Read a BltPixel from framebuffer at (x, y)
unsafe fn read_pixel_from_fb(
    fb: &FramebufferInfo,
    fb_ptr: *mut u8,
    x: usize,
    y: usize,
) -> BltPixel {
    let bytes_per_pixel = (fb.bits_per_pixel / 8) as usize;
    let offset = y * fb.bytes_per_line as usize + x * bytes_per_pixel;
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
        _ => BltPixel::default(),
    }
}

/// Create the Graphics Output Protocol from coreboot framebuffer info
///
/// # Returns
/// A pointer to the GraphicsOutputProtocol, or null on failure
pub fn create_gop(framebuffer: &FramebufferInfo) -> *mut GraphicsOutputProtocol {
    // Allocate mode info
    let mode_info_size = core::mem::size_of::<GopModeInfo>();
    let mode_info_ptr = match allocate_pool(MemoryType::BootServicesData, mode_info_size) {
        Ok(p) => p as *mut GopModeInfo,
        Err(_) => return core::ptr::null_mut(),
    };

    // Determine pixel format based on mask positions
    let (pixel_format, pixel_bitmask) = if framebuffer.bits_per_pixel == 32 {
        if framebuffer.red_mask_pos == 16
            && framebuffer.green_mask_pos == 8
            && framebuffer.blue_mask_pos == 0
        {
            // BGRA (most common)
            (
                PixelFormat::BlueGreenRedReserved8BitPerColor,
                PixelBitmask::default(),
            )
        } else if framebuffer.red_mask_pos == 0
            && framebuffer.green_mask_pos == 8
            && framebuffer.blue_mask_pos == 16
        {
            // RGBA
            (
                PixelFormat::RedGreenBlueReserved8BitPerColor,
                PixelBitmask::default(),
            )
        } else {
            // Custom bitmask
            let bitmask = PixelBitmask {
                red_mask: 0xFF << framebuffer.red_mask_pos,
                green_mask: 0xFF << framebuffer.green_mask_pos,
                blue_mask: 0xFF << framebuffer.blue_mask_pos,
                reserved_mask: 0,
            };
            (PixelFormat::BitMask, bitmask)
        }
    } else {
        // For non-32bpp, use bitmask
        let bitmask = PixelBitmask {
            red_mask: ((1u32 << framebuffer.red_mask_size) - 1) << framebuffer.red_mask_pos,
            green_mask: ((1u32 << framebuffer.green_mask_size) - 1) << framebuffer.green_mask_pos,
            blue_mask: ((1u32 << framebuffer.blue_mask_size) - 1) << framebuffer.blue_mask_pos,
            reserved_mask: 0,
        };
        (PixelFormat::BitMask, bitmask)
    };

    // Fill in mode info
    let mode_info = GopModeInfo {
        version: 0,
        horizontal_resolution: framebuffer.x_resolution,
        vertical_resolution: framebuffer.y_resolution,
        pixel_format,
        pixel_information: pixel_bitmask,
        pixels_per_scan_line: framebuffer.bytes_per_line / (framebuffer.bits_per_pixel as u32 / 8),
    };

    unsafe {
        core::ptr::write(mode_info_ptr, mode_info);
    }

    // Allocate GOP mode structure
    let mode_size = core::mem::size_of::<GopMode>();
    let mode_ptr = match allocate_pool(MemoryType::BootServicesData, mode_size) {
        Ok(p) => p as *mut GopMode,
        Err(_) => return core::ptr::null_mut(),
    };

    let gop_mode = GopMode {
        max_mode: 1, // We support 1 mode (mode 0)
        mode: 0,
        info: mode_info_ptr,
        size_of_info: mode_info_size,
        frame_buffer_base: framebuffer.physical_address,
        frame_buffer_size: framebuffer.size() as usize,
    };

    unsafe {
        core::ptr::write(mode_ptr, gop_mode);
    }

    // Allocate protocol structure
    let protocol_size = core::mem::size_of::<GraphicsOutputProtocol>();
    let protocol_ptr = match allocate_pool(MemoryType::BootServicesData, protocol_size) {
        Ok(p) => p as *mut GraphicsOutputProtocol,
        Err(_) => return core::ptr::null_mut(),
    };

    let protocol = GraphicsOutputProtocol {
        query_mode: gop_query_mode,
        set_mode: gop_set_mode,
        blt: gop_blt,
        mode: mode_ptr,
    };

    unsafe {
        core::ptr::write(protocol_ptr, protocol);
    }

    // Store global state for Blt operations
    state::console_mut().gop_framebuffer = Some(framebuffer.clone());

    log::info!(
        "GraphicsOutputProtocol created: {}x{} @ {:#x}, {:?}",
        framebuffer.x_resolution,
        framebuffer.y_resolution,
        framebuffer.physical_address,
        pixel_format
    );

    protocol_ptr
}
