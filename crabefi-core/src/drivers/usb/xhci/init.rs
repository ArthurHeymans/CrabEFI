//! xHCI controller init and port power.

use super::{IdentityMapper, MAX_SLOTS, TrbRing, XHCI_MMIO_SIZE, XhciError};
use crate::barrier;
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use xhci::extended_capabilities::{self, ExtendedCapability};
use xhci::registers::capability::CapabilityParameters1;
use xhci::registers::operational::PortStatusAndControlRegister;
use xhci::registers::{Access64, Doorbell, Registers};

impl super::XhciController {
    /// Take ownership of the controller from BIOS/SMM
    ///
    /// xHCI has an optional extended capability for BIOS ownership handoff.
    /// Unlike EHCI, xHCI extended capabilities are memory-mapped, not in PCI config space.
    /// The xECP (Extended Capabilities Pointer) is in HCCPARAMS1 bits 31:16.
    pub(super) fn take_bios_ownership(mmio_base: u64, hccparams1: CapabilityParameters1) {
        let Some(mut capabilities) = (unsafe {
            extended_capabilities::List::new(mmio_base as usize, hccparams1, IdentityMapper)
        }) else {
            return;
        };

        for capability in &mut capabilities {
            let Ok(ExtendedCapability::UsbLegacySupport(mut legacy)) = capability else {
                continue;
            };

            if legacy.usblegsup.read_volatile().hc_bios_owned_semaphore() {
                log::debug!("xHCI: Taking ownership from BIOS");
                legacy.usblegsup.update_volatile(|register| {
                    register.set_hc_os_owned_semaphore();
                });

                let timeout = Timeout::from_ms(1000);
                while !timeout.is_expired() {
                    if !legacy.usblegsup.read_volatile().hc_bios_owned_semaphore() {
                        log::debug!("xHCI: BIOS released ownership");
                        break;
                    }
                    crate::time::delay_ms(10);
                }
            }

            legacy.usblegctlsts.update_volatile(|register| {
                register
                    .clear_usb_smi_enable()
                    .clear_smi_on_host_system_error_enable()
                    .clear_smi_on_os_ownership_enable()
                    .clear_smi_on_pci_command_enable()
                    .clear_smi_on_bar_enable()
                    .clear_smi_on_os_ownership_change()
                    .clear_smi_on_pci_command()
                    .clear_smi_on_bar();
            });
            break;
        }
    }

    /// Create a new xHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, XhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(XhciError::NotReady)?;
        // SAFETY: mmio_base is a PCI BAR address for this xHCI controller,
        // mapped by the platform and valid for the device's lifetime.
        let mmio = unsafe {
            MmioRegion::try_new(mmio_base, XHCI_MMIO_SIZE).map_err(|e| {
                log::error!("xHCI MMIO region invalid at {mmio_base:#x}: {e}");
                XhciError::InvalidParameter
            })?
        };

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        let registers = unsafe {
            Registers::new_with_64bit_access(mmio_base as usize, IdentityMapper, Access64::LowHigh)
        };
        let hciversion = registers.capability.hciversion.read_volatile().get();
        let hccparams1 = registers.capability.hccparams1.read_volatile();
        let hcsparams1 = registers.capability.hcsparams1.read_volatile();
        let hcsparams2 = registers.capability.hcsparams2.read_volatile();

        let context_size = if hccparams1.context_size() { 64 } else { 32 };
        let num_scratchpad_bufs = hcsparams2.max_scratchpad_buffers() as u16;
        Self::take_bios_ownership(mmio_base, hccparams1);

        let num_ports = hcsparams1.number_of_ports();
        let hw_max_slots = hcsparams1.number_of_device_slots();
        // Cap to our Vec capacity
        let max_slots = (hw_max_slots as usize).min(MAX_SLOTS);

        log::info!(
            "xHCI version: {}.{}.{}, ports: {}, slots: {} (hw: {})",
            (hciversion >> 8) & 0xFF,
            (hciversion >> 4) & 0xF,
            hciversion & 0xF,
            num_ports,
            max_slots,
            hw_max_slots,
        );

        let page_size = u32::from(registers.operational.pagesize.read_volatile().get()) << 12;

        log::debug!(
            "xHCI: context_size={}, scratchpad_bufs={}",
            context_size,
            num_scratchpad_bufs
        );

        // Pre-fill slot Vec to max_slots entries (all None) so slot IDs
        // from the controller map directly to Vec indices.
        let mut slots = heapless::Vec::new();
        for _ in 0..max_slots {
            let _ = slots.push(None);
        }

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio,
            registers,
            num_ports,
            page_size,
            context_size,
            dcbaa: 0,
            scratchpad_array: 0,
            num_scratchpad_bufs,
            cmd_ring: TrbRing::empty(), // Will be initialized in init()
            erst: 0,
            event_ring: TrbRing::empty(), // Will be initialized in init()
            slots,
        };

        controller.init()?;

        // Give USB devices time to connect and be detected
        crate::time::delay_ms(50);

        controller.enumerate_ports()?;

        Ok(controller)
    }

    #[inline]
    pub(super) fn portsc(&self, port: u8) -> PortStatusAndControlRegister {
        self.registers
            .port_register_set
            .port(port as usize)
            .portsc
            .read_volatile()
    }

    pub(super) fn prepare_portsc_write(register: &mut PortStatusAndControlRegister) {
        register
            .set_0_port_enabled_disabled()
            .set_0_port_reset()
            .clear_port_link_state_write_strobe()
            .set_0_connect_status_change()
            .set_0_port_enabled_disabled_change()
            .set_0_warm_port_reset_change()
            .set_0_over_current_change()
            .set_0_port_reset_change()
            .set_0_port_link_state_change()
            .set_0_port_config_error_change()
            .set_0_warm_port_reset();
    }

    pub(super) fn update_portsc<F>(&mut self, port: u8, update: F)
    where
        F: FnOnce(&mut PortStatusAndControlRegister),
    {
        self.registers
            .port_register_set
            .port_mut(port as usize)
            .portsc
            .update_volatile(|register| {
                Self::prepare_portsc_write(register);
                update(register);
            });
    }

    pub(super) fn clear_port_changes(&mut self, port: u8) {
        self.update_portsc(port, |register| {
            register
                .clear_connect_status_change()
                .clear_port_enabled_disabled_change()
                .clear_warm_port_reset_change()
                .clear_over_current_change()
                .clear_port_reset_change()
                .clear_port_link_state_change()
                .clear_port_config_error_change();
        });
    }

    /// Ring a doorbell
    ///
    /// IMPORTANT: Caller must ensure memory barrier (fence) is executed
    /// before calling this to ensure all TRBs are visible to hardware.
    ///
    /// After writing the doorbell, a readback is performed to flush the PCI
    /// posted write buffer. Without this, the write may sit in a PCIe buffer
    /// and not reach the controller immediately (causing timeouts on some HW).
    /// This follows the Linux kernel's pattern in xhci-ring.c.
    #[inline]
    pub(super) fn ring_doorbell(&mut self, slot: u8, target: u8) {
        let mut doorbell = Doorbell::default();
        doorbell.set_doorbell_target(target);
        self.registers
            .doorbell
            .write_volatile_at(slot as usize, doorbell);
        let _ = self.registers.doorbell.read_volatile_at(slot as usize);
    }

    /// Initialize the controller
    pub(super) fn init(&mut self) -> Result<(), XhciError> {
        wait_for(100, || {
            !self
                .registers
                .operational
                .usbsts
                .read_volatile()
                .controller_not_ready()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.clear_run_stop();
            });
        wait_for(100, || {
            self.registers
                .operational
                .usbsts
                .read_volatile()
                .hc_halted()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.set_host_controller_reset();
            });
        crate::time::delay_ms(1);
        wait_for(500, || {
            !self
                .registers
                .operational
                .usbcmd
                .read_volatile()
                .host_controller_reset()
                && !self
                    .registers
                    .operational
                    .usbsts
                    .read_volatile()
                    .controller_not_ready()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.clear_interrupter_enable();
            });
        self.registers.operational.config.update_volatile(|config| {
            config.set_max_device_slots_enabled(self.slots.capacity() as u8);
        });

        // Allocate and set up DCBAA (Device Context Base Address Array)
        // DCBAA[0] is reserved for scratchpad buffer array pointer
        // DCBAA[1..max_slots] are for device context pointers
        let dcbaa_pages = ((self.slots.capacity() as u64 + 1) * 8).div_ceil(4096);
        let dcbaa_mem = efi::allocate_pages(dcbaa_pages).ok_or(XhciError::AllocationFailed)?;
        dcbaa_mem.fill(0);
        self.dcbaa = dcbaa_mem.as_ptr() as u64;

        // Allocate scratchpad buffers if needed
        // This is CRITICAL - many controllers (especially Intel) will fail with HSE
        // (Host System Error) if scratchpad buffers aren't allocated when required.
        if self.num_scratchpad_bufs > 0 {
            log::debug!(
                "xHCI: Allocating {} scratchpad buffers (page_size={})",
                self.num_scratchpad_bufs,
                self.page_size
            );

            // Allocate the scratchpad buffer array (array of u64 pointers)
            let sp_array_size = (self.num_scratchpad_bufs as u64) * 8;
            let sp_array_pages = sp_array_size.div_ceil(4096);
            let sp_array_mem =
                efi::allocate_pages(sp_array_pages).ok_or(XhciError::AllocationFailed)?;
            sp_array_mem.fill(0);
            self.scratchpad_array = sp_array_mem.as_ptr() as u64;

            // Allocate the actual scratchpad buffers (page-aligned, page-sized)
            // Each buffer must be page-aligned according to the controller's page size
            let page_size = self.page_size.max(4096) as usize;
            for i in 0..self.num_scratchpad_bufs as usize {
                // Allocate one page per scratchpad buffer
                let buf_pages = (page_size as u64).div_ceil(4096);
                let buf_mem = efi::allocate_pages(buf_pages).ok_or(XhciError::AllocationFailed)?;
                buf_mem.fill(0);
                let buf_addr = buf_mem.as_ptr() as u64;

                // Store pointer in scratchpad array
                let sp_array_entry = (self.scratchpad_array + (i as u64 * 8)) as *mut u64;
                unsafe {
                    ptr::write_volatile(sp_array_entry, buf_addr);
                }
            }

            // Store scratchpad array pointer in DCBAA[0]
            let dcbaa_entry0 = self.dcbaa as *mut u64;
            unsafe {
                ptr::write_volatile(dcbaa_entry0, self.scratchpad_array);
            }

            log::debug!(
                "xHCI: Scratchpad array at {:#x}, stored in DCBAA[0]",
                self.scratchpad_array
            );
        }

        // Publish DMA structures before programming their MMIO base address.
        barrier::mmio_write();

        let mut dcbaap =
            xhci::registers::operational::DeviceContextBaseAddressArrayPointerRegister::default();
        dcbaap.set(self.dcbaa);
        self.registers.operational.dcbaap.write_volatile(dcbaap);

        // Allocate command ring (256 TRBs)
        let cmd_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let cmd_ring_base = cmd_ring_mem.as_ptr() as u64;
        self.cmd_ring = TrbRing::new(cmd_ring_base, 256);

        // Set command ring pointer
        self.registers.operational.crcr.update_volatile(|crcr| {
            crcr.set_0_command_stop().set_0_command_abort();
            crcr.set_command_ring_pointer(self.cmd_ring.base);
            if self.cmd_ring.cycle {
                crcr.set_ring_cycle_state();
            } else {
                crcr.clear_ring_cycle_state();
            }
        });

        // Allocate event ring (256 TRBs) - no link TRB for event rings
        let event_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let event_ring_base = event_ring_mem.as_ptr() as u64;
        self.event_ring = TrbRing::new_event_ring(event_ring_base, 256);

        // Allocate Event Ring Segment Table (ERST)
        let erst_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        erst_mem.fill(0);
        self.erst = erst_mem.as_ptr() as u64;

        // Set up ERST entry (xHCI spec 6.5)
        // Structure: u64 base address, u32 size, u32 reserved
        unsafe {
            let erst_base = self.erst as *mut u64;
            let erst_size = (self.erst + 8) as *mut u32;
            ptr::write_volatile(erst_base, event_ring_base); // Ring Segment Base Address (64-bit)
            ptr::write_volatile(erst_size, 256); // Ring Segment Size (32-bit, number of TRBs)
        }

        {
            let mut interrupter = self.registers.interrupter_register_set.interrupter_mut(0);
            interrupter.erstsz.update_volatile(|erstsz| {
                erstsz.set(1);
            });
            interrupter.erdp.update_volatile(|erdp| {
                erdp.set_event_ring_dequeue_pointer(event_ring_base);
                erdp.clear_event_handler_busy();
            });
            interrupter.erstba.update_volatile(|erstba| {
                erstba.set(self.erst);
            });
            interrupter.iman.update_volatile(|iman| {
                iman.set_0_interrupt_pending().set_interrupt_enable();
            });
        }

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.set_run_stop().set_interrupter_enable();
            });
        wait_for(100, || {
            !self
                .registers
                .operational
                .usbsts
                .read_volatile()
                .hc_halted()
        });

        // Power on all ports - many real hardware controllers require explicit port power
        self.power_on_ports();

        log::info!("xHCI controller initialized");
        Ok(())
    }

    /// Power on all ports
    ///
    /// Many xHCI controllers (especially on real hardware) require explicit
    /// port power enable. Without this, devices won't be detected.
    pub(super) fn power_on_ports(&mut self) {
        for port in 0..self.num_ports {
            if self.portsc(port).port_power() {
                continue;
            }
            self.update_portsc(port, |portsc| {
                portsc.set_port_power();
            });
            log::debug!("xHCI: Powered on port {}", port);
        }
        crate::time::delay_ms(20);
    }
}
