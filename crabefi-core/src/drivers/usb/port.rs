//! USB bus enumeration. Root and external hub ports use the same lifecycle.

use super::controller::{
    ConfigurationInfo, UsbController, UsbDevice, UsbError, allocate_legacy_address,
    configuration_length, desc_type, hub_feature, hub_port_change, hub_port_status,
    parse_configuration_checked, req_type, request,
};
use super::{UsbSpeed, with_controller, with_port_controller};
use crate::cell::{Local, LocalCell};
use crate::exec::{self, BoxFuture};
use crate::time::Timeout;
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::{future::poll_fn, task::Poll};
use embassy_futures::select::select;

const CONNECTION_TIMEOUT_MS: u64 = 1000;
/// Do not start another poll after this deadline. A synchronous transfer
/// already in flight can finish after it.
const BOOT_DISCOVERY_CAP_MS: u64 = 10_000;
const MIGRATION_QUIET_MS: u64 = 500;
const MAX_PORT_ATTEMPTS: usize = 3;
const PORT_RETRY_MS: u64 = 250;
const DEBOUNCE_MS: u64 = 100;
const ROOT_POLL_MS: u64 = 25;
const HUB_POLL_MS: u64 = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RootKind {
    Ehci,
    Ohci,
    #[cfg(target_arch = "x86_64")]
    Uhci,
    #[cfg(feature = "xhci")]
    Xhci,
}

#[derive(Clone, Copy, Default)]
pub(super) struct RootStatus {
    pub(super) connected: bool,
    pub(super) changed: bool,
    pub(super) enabled: bool,
    pub(super) resetting: bool,
    pub(super) low_speed: bool,
    #[cfg(feature = "xhci")]
    pub(super) speed_id: u8,
    #[cfg(feature = "xhci")]
    pub(super) superspeed: bool,
    #[cfg(feature = "xhci")]
    pub(super) link_state: u8,
    #[cfg(feature = "xhci")]
    pub(super) reset_done: bool,
    #[cfg(feature = "xhci")]
    pub(super) warm_reset_done: bool,
}

#[allow(dead_code)] // Some commands are specific to a host controller or architecture.
#[derive(Clone, Copy)]
pub(super) enum RootCommand {
    ClearChanges,
    Reset,
    EndReset,
    Enable,
    Disable,
    Handoff,
    #[cfg(feature = "xhci")]
    WarmReset,
    AckReset,
    #[cfg(feature = "xhci")]
    AckWarmReset,
}

pub(super) trait PortController: UsbController {
    fn root_ports(&self) -> (RootKind, u8);
    fn root_status(&self, port: u8) -> RootStatus;
    fn root_command(&mut self, port: u8, command: RootCommand);

    fn legacy_devices(&mut self) -> Option<(&mut [Option<UsbDevice>], &mut u8)> {
        None
    }

    fn legacy_control(
        &mut self,
        _device: &UsbDevice,
        _request: Control,
        _data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        Err(UsbError::NotSupported)
    }

    fn poll_bus(&mut self) {}
}

#[derive(Clone, Copy)]
pub(super) struct Control {
    pub(super) ty: u8,
    pub(super) request: u8,
    pub(super) value: u16,
    pub(super) index: u16,
}

impl Control {
    pub(super) const fn new(ty: u8, request: u8, value: u16, index: u16) -> Self {
        Self {
            ty,
            request,
            value,
            index,
        }
    }

    pub(super) const fn descriptor(ty: u8, descriptor: u8, index: u16) -> Self {
        Self::new(
            req_type::DIR_IN | ty,
            request::GET_DESCRIPTOR,
            (descriptor as u16) << 8,
            index,
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct Pipe {
    pub(super) controller: usize,
    pub(super) address: u8,
}

impl Pipe {
    pub(super) async fn control(
        self,
        request: Control,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        transfer().await;
        let result = self.control_now(request, data);
        if result.is_ok() {
            note_startup_progress();
        }
        result
    }

    fn control_now(self, request: Control, data: Option<&mut [u8]>) -> Result<usize, UsbError> {
        with_controller(self.controller, |host| {
            host.control_transfer(
                self.address,
                request.ty,
                request.request,
                request.value,
                request.index,
                data,
            )
        })
        .ok_or(UsbError::Disconnected)?
    }

    #[cfg(feature = "xhci")]
    pub(super) async fn configuration(self) -> Result<ConfigurationInfo, UsbError> {
        read_configuration(async |buffer| {
            self.control(
                Control::descriptor(req_type::RCPT_DEVICE, desc_type::CONFIGURATION, 0),
                Some(buffer),
            )
            .await
        })
        .await
    }
}

pub(super) async fn hid_report(
    endpoint: u8,
    control: &mut impl AsyncFnMut(Control, Option<&mut [u8]>) -> Result<usize, UsbError>,
) -> Result<(u8, Option<Vec<u8>>), UsbError> {
    let config = read_configuration(async |buffer| {
        control(
            Control::descriptor(req_type::RCPT_DEVICE, desc_type::CONFIGURATION, 0),
            Some(buffer),
        )
        .await
    })
    .await?;
    let iface = config.interfaces[..config.num_interfaces]
        .iter()
        .find(|iface| {
            (iface.is_hid_keyboard() || iface.is_hid_mouse())
                && iface
                    .find_interrupt_in()
                    .is_some_and(|ep| ep.number == endpoint)
        })
        .ok_or(UsbError::DeviceNotFound)?;
    let number = iface.interface_number;
    let length = usize::from(iface.hid_report_descriptor_length);
    if !(1..=4096).contains(&length) {
        return Ok((number, None));
    }
    let mut data = alloc::vec![0; length];
    let result = control(
        Control::descriptor(
            req_type::RCPT_INTERFACE,
            desc_type::HID_REPORT,
            u16::from(number),
        ),
        Some(&mut data),
    )
    .await;
    match result {
        Ok(actual) if actual == length => Ok((number, Some(data))),
        Err(error @ (UsbError::Timeout | UsbError::Disconnected | UsbError::DeviceNotFound)) => {
            Err(error)
        }
        // EP0 STALL and an absent/unsupported descriptor do not preclude
        // HID boot protocol, which does not require a report descriptor.
        _ => Ok((number, None)),
    }
}

#[cfg(test)]
pub(super) fn fake_hid_descriptor(
    value: u16,
    index: u16,
    data: &mut [u8],
    interface: u8,
    endpoint: u8,
    protocol: u8,
    report: Option<&[u8]>,
) -> Result<usize, UsbError> {
    let length = u16::try_from(report.map_or(0, <[u8]>::len))
        .unwrap()
        .to_le_bytes();
    let config = [
        9,
        desc_type::CONFIGURATION,
        34,
        0,
        1,
        1,
        0,
        0x80,
        50,
        9,
        desc_type::INTERFACE,
        interface,
        0,
        1,
        3,
        1,
        protocol,
        0,
        9,
        desc_type::HID,
        0x11,
        1,
        0,
        1,
        desc_type::HID_REPORT,
        length[0],
        length[1],
        7,
        desc_type::ENDPOINT,
        0x80 | endpoint,
        3,
        8,
        0,
        10,
    ];
    let bytes = match (value >> 8) as u8 {
        desc_type::CONFIGURATION => {
            assert_eq!(index, 0);
            &config
        }
        desc_type::HID_REPORT => {
            assert_eq!(index, u16::from(interface));
            report.ok_or(UsbError::NotSupported)?
        }
        _ => unreachable!("unexpected descriptor request"),
    };
    let count = bytes.len().min(data.len());
    data[..count].copy_from_slice(&bytes[..count]);
    Ok(count)
}

pub(super) async fn read_configuration(
    mut read: impl AsyncFnMut(&mut [u8]) -> Result<usize, UsbError>,
) -> Result<ConfigurationInfo, UsbError> {
    let mut header = [0; 9];
    let actual = read(&mut header).await?;
    let length = configuration_length(&header, actual)?;
    let mut buffer = alloc::vec![0; length];
    if read(&mut buffer).await? != length {
        return Err(UsbError::InvalidParameter);
    }
    parse_configuration_checked(&buffer)
}

// A transfer is synchronous. Grant at most one per idle poll, in FIFO
// order across all leaves, including the watcher and binder within a port.
struct TransferBudget {
    queued: Local<VecDeque<u64>>,
    next: LocalCell<u64>,
    available: LocalCell<bool>,
}
impl TransferBudget {
    const fn new() -> Self {
        Self {
            queued: Local::new(VecDeque::new()),
            next: LocalCell::new(0),
            available: LocalCell::new(false),
        }
    }

    async fn take(&self) {
        let id = self.next.get();
        self.next.set(id.wrapping_add(1));
        self.queued.borrow_mut().push_back(id);
        let mut ticket = TransferTicket {
            budget: self,
            id,
            pending: true,
        };
        poll_fn(|_| {
            if !self.available.get() {
                return Poll::Pending;
            }
            let mut queued = self.queued.borrow_mut();
            if queued.front() != Some(&id) {
                return Poll::Pending;
            }
            queued.pop_front();
            ticket.pending = false;
            self.available.set(false);
            Poll::Ready(())
        })
        .await;
    }
}

struct TransferTicket<'a> {
    budget: &'a TransferBudget,
    id: u64,
    pending: bool,
}
impl Drop for TransferTicket<'_> {
    fn drop(&mut self) {
        if self.pending {
            // Removal can drop a hub tree with outstanding requests. A dead
            // ticket at the head would otherwise stop the entire bus.
            self.budget.queued.borrow_mut().retain(|&id| id != self.id);
        }
    }
}

static TRANSFERS: TransferBudget = TransferBudget::new();

pub(super) async fn transfer() {
    TRANSFERS.take().await;
}

// Only one device may use address zero on a shared USB2/USB1 bus. This
// reservation serializes port resets, not controller access: foreground I/O
// to addressed devices and hub status reads remain possible while it is held.
static DEFAULT_ADDRESSES: Local<Vec<Rc<LocalCell<bool>>>> = Local::new(Vec::new());

struct DefaultAddress(Rc<LocalCell<bool>>);
impl DefaultAddress {
    async fn reserve(controller: usize) -> Self {
        let owner = DEFAULT_ADDRESSES.borrow()[controller].clone();
        Self::reserve_on(owner).await
    }

    async fn reserve_on(owner: Rc<LocalCell<bool>>) -> Self {
        poll_fn(|_| {
            if owner.get() {
                Poll::Pending
            } else {
                owner.set(true);
                Poll::Ready(())
            }
        })
        .await;
        Self(owner)
    }
}
impl Drop for DefaultAddress {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

static STARTUP_PROGRESS: LocalCell<u64> = LocalCell::new(0);
static COMPANION_HANDOFF: LocalCell<u64> = LocalCell::new(0);
static COMPANION_SCANS: Local<Vec<u64>> = Local::new(Vec::new());

/// Record successful discovery stages, not background status monitoring.
pub(super) fn note_startup_progress() {
    STARTUP_PROGRESS.update(|progress| *progress = progress.wrapping_add(1));
}

static STARTUP_ACTIVE: LocalCell<usize> = LocalCell::new(0);
static STARTUP_MOVED: LocalCell<bool> = LocalCell::new(false);
struct StartupActivity<'a>(&'a LocalCell<usize>);
impl<'a> StartupActivity<'a> {
    fn new(active: &'a LocalCell<usize>) -> Self {
        active.update(|n| *n += 1);
        Self(active)
    }
}
impl Drop for StartupActivity<'_> {
    fn drop(&mut self) {
        self.0.update(|n| *n -= 1);
    }
}

/// Poll the live bus tasks during initial discovery, including the window
/// for late first connections and devices migrating between root ports.
pub(super) async fn settle() {
    if super::controller_count() == 0 {
        return;
    }
    STARTUP_MOVED.set(false);
    let now_ms = || crate::time::read_counter() / (crate::time::counter_frequency() / 1000).max(1);
    let started_ms = now_ms();
    let mut drain = BootDrain::new(started_ms, STARTUP_PROGRESS.get());
    wait_for_first_port(exec::sleep_ms(CONNECTION_TIMEOUT_MS), || {
        if drain.capped(now_ms()) {
            return true;
        }
        exec::poll_background();
        STARTUP_ACTIVE.get() != 0
    })
    .await;
    // Give active discovery its inactivity window without restarting the
    // overall cap after the first-connection wait.
    drain.last_ms = now_ms();
    poll_fn(|_| {
        if drain.capped(now_ms()) {
            return Poll::Ready(());
        }
        exec::poll_background();
        let handoff = COMPANION_HANDOFF.get();
        let companions_ready = COMPANION_SCANS.borrow().iter().all(|last| *last == handoff);
        let quiet_ms = if STARTUP_MOVED.get() {
            MIGRATION_QUIET_MS
        } else if handoff != 0 {
            ROOT_POLL_MS * 2
        } else {
            0
        };
        if drain.settled(
            now_ms(),
            STARTUP_PROGRESS.get(),
            STARTUP_ACTIVE.get(),
            companions_ready,
            quiet_ms,
        ) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    let active = STARTUP_ACTIVE.get();
    if active != 0 {
        // Discovery continues in the background; boot does not wait.
        log::warn!(
            "USB: boot stopped waiting after {} ms with {} port(s) still busy",
            now_ms().saturating_sub(started_ms),
            active
        );
    }
}

struct BootDrain {
    started_ms: u64,
    last_ms: u64,
    progress: u64,
}
impl BootDrain {
    fn new(now_ms: u64, progress: u64) -> Self {
        Self {
            started_ms: now_ms,
            last_ms: now_ms,
            progress,
        }
    }

    fn capped(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_ms) >= BOOT_DISCOVERY_CAP_MS
    }

    fn settled(
        &mut self,
        now_ms: u64,
        progress: u64,
        active: usize,
        companions_ready: bool,
        quiet_ms: u64,
    ) -> bool {
        if progress != self.progress {
            self.last_ms = now_ms;
            self.progress = progress;
        }
        let idle_ms = now_ms.saturating_sub(self.last_ms);
        // A wedged transfer does not renew discovery indefinitely. On an
        // answering device each completed stage renews this window, but
        // only up to the cap: a port that keeps "progressing" without ever
        // finishing must not hold the boot.
        self.capped(now_ms)
            || idle_ms >= CONNECTION_TIMEOUT_MS
            || (active == 0 && companions_ready && idle_ms >= quiet_ms)
    }
}

// Check for activity before the deadline on every poll, including the last.
async fn wait_for_first_port(
    deadline: impl core::future::Future<Output = ()>,
    mut started: impl FnMut() -> bool,
) {
    select(
        poll_fn(|_| {
            if started() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
        deadline,
    )
    .await;
}

pub(super) async fn buses() {
    let mut initialized = 0;
    let mut ports = PortTasks::default();
    poll_fn(|cx| {
        TRANSFERS.available.set(true);
        let count = super::controller_count();
        for controller in initialized..count {
            if let Some((kind, count)) = with_port_controller(controller, |host| host.root_ports())
            {
                DEFAULT_ADDRESSES
                    .borrow_mut()
                    .push(Rc::new(LocalCell::new(false)));
                for number in 0..count {
                    // Keep a fresh sample from every OHCI/UHCI root port
                    // before declaring an EHCI ownership handoff settled.
                    let companion_scan = match kind {
                        RootKind::Ohci => true,
                        #[cfg(target_arch = "x86_64")]
                        RootKind::Uhci => true,
                        _ => false,
                    }
                    .then(|| {
                        let mut scans = COMPANION_SCANS.borrow_mut();
                        let index = scans.len();
                        scans.push(COMPANION_HANDOFF.get());
                        index
                    });
                    ports.add(
                        Port {
                            controller,
                            kind,
                            number,
                            root_number: number,
                            hub: None,
                            companion_scan,
                            #[cfg(test)]
                            test_root: None,
                        },
                        0,
                    );
                }
            }
        }
        initialized = count;
        for controller in 0..initialized {
            with_port_controller(controller, |host| host.poll_bus());
        }
        ports.poll(cx);
        Poll::<()>::Pending
    })
    .await;
}

#[derive(Default)]
struct PortTasks {
    ports: Vec<BoxFuture<'static, ()>>,
    first: usize,
}

impl PortTasks {
    fn add(&mut self, port: Port, initial_scans: u8) {
        let initial_scan = (initial_scans != 0).then(|| StartupActivity::new(&STARTUP_ACTIVE));
        self.ports
            .push(Box::pin(port_task(port, initial_scans, initial_scan)));
    }

    fn poll(&mut self, cx: &mut core::task::Context<'_>) {
        let count = self.ports.len();
        if count != 0 {
            for step in 0..count {
                let i = (self.first + step) % count;
                let _ = self.ports[i].as_mut().poll(cx);
            }
            self.first = (self.first + 1) % count;
        }
    }

    async fn run(mut self) {
        poll_fn(|cx| {
            self.poll(cx);
            Poll::<()>::Pending
        })
        .await;
    }
}

struct Hub {
    address: u8,
    #[cfg(feature = "xhci")]
    superspeed: bool,
    upstream: Option<Rc<Hub>>,
    transport_failures: LocalCell<u8>,
    quarantine: Local<Option<DefaultAddress>>,
}

const HUB_TRANSPORT_FAILURE_LIMIT: u8 = 3;

impl Hub {
    fn root_hub(&self) -> &Hub {
        let mut hub = self;
        while let Some(upstream) = &hub.upstream {
            hub = upstream;
        }
        hub
    }

    fn parked(&self) -> bool {
        self.transport_failures.get() >= HUB_TRANSPORT_FAILURE_LIMIT
            || self.quarantine.borrow().is_some()
            || self.upstream.as_ref().is_some_and(|hub| hub.parked())
    }

    fn isolate_or_quarantine(
        &self,
        reservation: DefaultAddress,
        disabled: bool,
        upstream: RootStatus,
    ) {
        if !disabled && upstream.connected && !upstream.changed {
            // Address zero might still respond. Keep the reservation for
            // this hub attachment, but leave addressed transfers available.
            assert!(self.quarantine.borrow().is_none());
            *self.quarantine.borrow_mut() = Some(reservation);
            log::warn!(
                "USB hub {} port disable unconfirmed; quarantining address zero until disconnect",
                self.address
            );
        }
    }

    fn note_transport_success(&self) {
        if !self.parked() {
            self.transport_failures.set(0);
        }
    }

    fn note_transport_failure(&self) {
        if !self.parked() {
            self.transport_failures.update(|count| *count += 1);
            if self.parked() {
                log::warn!(
                    "USB hub {} repeatedly failed requests; monitoring its upstream port only",
                    self.address
                );
            }
        }
    }
}

#[derive(Clone)]
struct Port {
    controller: usize,
    kind: RootKind,
    number: u8,
    root_number: u8,
    companion_scan: Option<usize>,
    #[cfg(test)]
    test_root: Option<Rc<tests::TestRoot>>,
    hub: Option<Rc<Hub>>,
}

#[derive(Clone, Copy)]
enum PortSpeed {
    Legacy(UsbSpeed),
    #[cfg(feature = "xhci")]
    Xhci(u8),
}

#[derive(Clone, Copy, Default)]
struct Connection {
    connected: bool,
    changed: bool,
}

trait PortOps {
    async fn connection(&self) -> Result<Connection, UsbError>;
    async fn clear_change(&self) -> Result<(), UsbError>;
    async fn bring_up(&self, retry: bool) -> Result<Option<u8>, UsbError>;
    fn observe_failed_bring_up(&self) {}
    async fn attached(&self, address: u8, startup: StartupActivity<'_>);
    fn startup(&self) -> StartupActivity<'_>;
    async fn detach(&self, address: u8);
    fn interval(&self) -> u64;
    fn upstream_parked(&self) -> bool {
        false
    }
    /// The port stops retrying until its connection changes.
    fn report_parked(&self, _error: &UsbError) {}
    async fn sleep(&self, ms: u64) {
        exec::sleep_ms(ms).await;
    }
}

async fn port_task(
    port: impl PortOps,
    mut initial_scans: u8,
    mut initial_scan: Option<StartupActivity<'_>>,
) {
    'connect: loop {
        let mut clear_failures = 0usize;
        loop {
            if let Ok(connection) = port.connection().await {
                if connection.changed {
                    match port.clear_change().await {
                        Ok(()) => clear_failures = 0,
                        Err(error) => {
                            clear_failures += 1;
                            if clear_failures >= MAX_PORT_ATTEMPTS {
                                initial_scans = 0;
                                drop(initial_scan.take());
                                port.report_parked(&error);
                                wait_for_replug(&port, connection.connected, false).await;
                                continue 'connect;
                            }
                            port.sleep(port.interval()).await;
                            continue;
                        }
                    }
                } else {
                    clear_failures = 0;
                }
                if connection.connected {
                    initial_scans = 0;
                    break;
                }
                if let Some(left) = initial_scans.checked_sub(1) {
                    initial_scans = left;
                    note_startup_progress();
                    if initial_scans == 0 {
                        drop(initial_scan.take());
                    }
                }
            } else if port.upstream_parked() {
                initial_scans = 0;
                drop(initial_scan.take());
            }
            port.sleep(port.interval()).await;
        }

        let startup = initial_scan.take().unwrap_or_else(|| port.startup());
        let address = 'enumerate: {
            let mut change_cleared = false;
            for attempt in 1..=MAX_PORT_ATTEMPTS {
                port.sleep(DEBOUNCE_MS).await;
                let link = port.connection().await;
                let unstable = matches!(&link, Ok(link) if link.changed);
                let result = match link {
                    Ok(link) if !link.connected => {
                        port.observe_failed_bring_up();
                        continue 'connect;
                    }
                    Ok(link) if !link.changed => port.bring_up(attempt > 1).await,
                    Ok(_) => Err(UsbError::NotReady),
                    Err(error) => Err(error),
                };
                match result {
                    Ok(Some(address)) => break 'enumerate address,
                    Ok(None) => continue 'connect,
                    Err(error) => {
                        port.observe_failed_bring_up();
                        match port.connection().await {
                            // Only a device that left gets a new budget. A
                            // change latched while it stayed connected can be
                            // caused by our own reset: restarting on it would
                            // reset the port forever.
                            Ok(link) if !link.connected => continue 'connect,
                            Ok(link) if link.changed => {
                                if port.clear_change().await.is_ok() {
                                    match port.connection().await {
                                        Ok(after) if !after.connected => continue 'connect,
                                        Ok(after) => change_cleared = !after.changed,
                                        Err(_) => change_cleared = false,
                                    }
                                } else {
                                    change_cleared = false;
                                }
                            }
                            Ok(_) => {
                                change_cleared = true;
                            }
                            Err(_) => {
                                change_cleared = false;
                            }
                        }
                        log::debug!(
                            "USB port enumeration attempt {attempt}/{MAX_PORT_ATTEMPTS} failed: {error:?}"
                        );
                        if attempt == MAX_PORT_ATTEMPTS {
                            port.report_parked(&error);
                        }
                        if !unstable && attempt != MAX_PORT_ATTEMPTS {
                            let retry_ms = if matches!(error, UsbError::Timeout) {
                                CONNECTION_TIMEOUT_MS
                            } else {
                                PORT_RETRY_MS
                            };
                            port.sleep(retry_ms).await;
                        }
                    }
                }
            }
            drop(startup);
            // A parked port wakes on disconnect, or on a fresh change once the
            // change latch has been observed clear.
            wait_for_replug(&port, true, change_cleared).await;
            continue 'connect;
        };

        // Poll the parent first. On disconnect or upstream hub parking,
        // cancellation drops any live child tasks before teardown.
        select(wait_for_port_change(&port), async {
            port.attached(address, startup).await;
            core::future::pending::<()>().await;
        })
        .await;
        let _ = port.clear_change().await;
        port.detach(address).await;
    }
}

async fn wait_for_port_change(port: &impl PortOps) {
    loop {
        port.sleep(port.interval()).await;
        if port.upstream_parked() {
            return;
        }
        if let Ok(connection) = port.connection().await
            && (!connection.connected || connection.changed)
        {
            return;
        }
    }
}

async fn wait_for_replug(port: &impl PortOps, parked_connected: bool, mut change_cleared: bool) {
    loop {
        port.sleep(port.interval()).await;
        if port.upstream_parked() {
            return;
        }
        if let Ok(connection) = port.connection().await {
            if connection.connected != parked_connected {
                return;
            }
            if connection.changed {
                if change_cleared {
                    return;
                }
            } else {
                change_cleared = true;
            }
        }
    }
}

async fn retry_storage_probe(
    port: &impl PortOps,
    mut result: Result<(), super::mass_storage::MassStorageError>,
    mut probe: impl AsyncFnMut() -> Result<(), super::mass_storage::MassStorageError>,
) {
    // Readiness is a positive response from the device, not a failed transfer.
    while matches!(result, Err(super::mass_storage::MassStorageError::NotReady)) {
        port.sleep(CONNECTION_TIMEOUT_MS).await;
        result = probe().await;
    }
}

impl Port {
    fn shares_default_address(&self) -> bool {
        #[cfg(feature = "xhci")]
        if self.kind == RootKind::Xhci {
            // Root ports and SuperSpeed routes are isolated by the xHC.
            return self.hub.as_ref().is_some_and(|hub| !hub.superspeed);
        }
        true
    }

    fn root_status(&self) -> RootStatus {
        #[cfg(test)]
        if let Some(root) = &self.test_root {
            return root.status.get();
        }
        with_port_controller(self.controller, |host| host.root_status(self.root_number))
            .unwrap_or_default()
    }

    fn root_command(&self, command: RootCommand) {
        debug_assert!(self.hub.is_none());
        #[cfg(test)]
        if let Some(root) = &self.test_root {
            root.command(command);
            return;
        }
        if matches!(command, RootCommand::Handoff) {
            COMPANION_HANDOFF.update(|epoch| *epoch = epoch.wrapping_add(1));
            note_startup_progress();
        }
        with_port_controller(self.controller, |host| {
            host.root_command(self.root_number, command)
        });
    }

    async fn hub_control(
        &self,
        ty: u8,
        request: u8,
        value: u16,
        data: Option<&mut [u8]>,
        submitted: Option<&mut bool>,
    ) -> Result<usize, UsbError> {
        let hub = self.hub.as_ref().ok_or(UsbError::InvalidParameter)?;
        if hub.parked() {
            return Err(UsbError::NotReady);
        }
        transfer().await;
        if hub.parked() {
            return Err(UsbError::NotReady);
        }
        // A root hub can vanish while its child task is waiting for a turn.
        // Consult PORTSC before issuing a request that cannot get a reply.
        let upstream = self.root_status();
        if !upstream.connected || upstream.changed {
            return Err(UsbError::Disconnected);
        }
        if let Some(submitted) = submitted {
            *submitted = true;
        }
        let result = Pipe {
            controller: self.controller,
            address: hub.address,
        }
        .control_now(
            Control::new(
                ty | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request,
                value,
                u16::from(self.number),
            ),
            data,
        );
        // GET_STATUS also needs to validate the returned length. Count
        // consecutive transport failures here so a hub that answers status
        // but times out clearing a change latch cannot hang every idle poll.
        if request != super::controller::request::GET_STATUS {
            match &result {
                Ok(_) => hub.note_transport_success(),
                Err(error) if !matches!(error, UsbError::Stall | UsbError::NotSupported) => {
                    hub.note_transport_failure();
                }
                Err(_) => {}
            }
        }
        result
    }

    async fn hub_status(&self) -> Result<(u16, u16), UsbError> {
        let hub = self.hub.as_ref().ok_or(UsbError::InvalidParameter)?;
        let mut buf = [0; 4];
        let result = self
            .hub_control(
                req_type::DIR_IN,
                request::GET_STATUS,
                0,
                Some(&mut buf),
                None,
            )
            .await;
        let result = result.and_then(|length| {
            if length != buf.len() {
                return Err(UsbError::InvalidParameter);
            }
            Ok((
                u16::from_le_bytes([buf[0], buf[1]]),
                u16::from_le_bytes([buf[2], buf[3]]),
            ))
        });
        if result.is_ok() {
            hub.note_transport_success();
        } else {
            let upstream = self.root_status();
            if upstream.connected && !upstream.changed {
                hub.note_transport_failure();
            }
        }
        result
    }

    async fn hub_feature(&self, request: u8, feature: u16) -> Result<(), UsbError> {
        self.hub_control(req_type::DIR_OUT, request, feature, None, None)
            .await
            .map(|_| ())
    }

    async fn reset(
        &self,
        _retry: bool,
        reset_submitted: &mut bool,
    ) -> Result<Option<PortSpeed>, UsbError> {
        if let Some(_hub) = self.hub.as_ref() {
            self.hub_control(
                req_type::DIR_OUT,
                request::SET_FEATURE,
                hub_feature::PORT_RESET,
                None,
                Some(reset_submitted),
            )
            .await?;
            note_startup_progress();
            exec::sleep_ms(60).await;
            let deadline = Timeout::from_ms(500);
            loop {
                let (status, change) = self.hub_status().await?;
                if status & hub_port_status::CONNECTION == 0 {
                    return Err(UsbError::Disconnected);
                }
                if change & hub_port_change::C_RESET != 0 {
                    self.hub_feature(request::CLEAR_FEATURE, hub_feature::C_PORT_RESET)
                        .await?;
                    note_startup_progress();
                    if status & hub_port_status::ENABLE == 0 {
                        return Err(UsbError::NotReady);
                    }
                    exec::sleep_ms(10).await;
                    #[cfg(feature = "xhci")]
                    if self.kind == RootKind::Xhci {
                        let pipe = Pipe {
                            controller: self.controller,
                            address: _hub.address,
                        };
                        let speed = if _hub.superspeed {
                            super::xhci::enumerate::superspeed_hub_port_speed(pipe, self.number)
                                .await?
                        } else if status & hub_port_status::HIGH_SPEED != 0 {
                            3
                        } else if status & hub_port_status::LOW_SPEED != 0 {
                            2
                        } else {
                            1
                        };
                        return Ok(Some(PortSpeed::Xhci(speed)));
                    }
                    let speed = if status & hub_port_status::HIGH_SPEED != 0
                        && self.kind == RootKind::Ehci
                    {
                        UsbSpeed::High
                    } else if status & hub_port_status::LOW_SPEED != 0 {
                        UsbSpeed::Low
                    } else {
                        UsbSpeed::Full
                    };
                    return Ok(Some(PortSpeed::Legacy(speed)));
                }
                if deadline.is_expired() {
                    return Err(UsbError::NotReady);
                }
                exec::sleep_ms(10).await;
            }
        }

        let status = self.root_status();
        if !status.connected {
            return Err(UsbError::Disconnected);
        }
        match self.kind {
            RootKind::Ehci => {
                if status.low_speed {
                    log::debug!(
                        "EHCI: Port {} has low-speed device, releasing to companion",
                        self.number
                    );
                    self.root_command(RootCommand::Handoff);
                    return Ok(None);
                }
                *reset_submitted = true;
                self.root_command(RootCommand::Reset);
                exec::sleep_ms(50).await;
                self.root_command(RootCommand::EndReset);
                exec::sleep_ms(100).await;
                exec::wait_for(250, || {
                    let status = self.root_status();
                    status.enabled || !status.connected
                })
                .await;
                let status = self.root_status();
                if !status.connected {
                    return Err(UsbError::Disconnected);
                }
                if !status.enabled {
                    log::debug!(
                        "EHCI: Port {} has full-speed device, releasing to companion",
                        self.number
                    );
                    self.root_command(RootCommand::Handoff);
                    return Ok(None);
                }
                // EHCI's boot path has always acknowledged its changes
                // here, before the final recovery delay.
                self.root_command(RootCommand::ClearChanges);
                exec::sleep_ms(50).await;
                Ok(Some(PortSpeed::Legacy(UsbSpeed::High)))
            }
            RootKind::Ohci => {
                *reset_submitted = true;
                self.root_command(RootCommand::Reset);
                exec::wait_for(100, || !self.root_status().resetting).await;
                exec::sleep_ms(10).await;
                self.root_command(RootCommand::AckReset);
                let status = self.root_status();
                if !status.enabled {
                    return Err(UsbError::NotReady);
                }
                Ok(Some(PortSpeed::Legacy(UsbSpeed::from_ohci(
                    status.low_speed,
                ))))
            }
            #[cfg(target_arch = "x86_64")]
            RootKind::Uhci => {
                *reset_submitted = true;
                self.root_command(RootCommand::Reset);
                exec::sleep_ms(50).await;
                self.root_command(RootCommand::EndReset);
                exec::sleep_ms(10).await;
                for _ in 0..10 {
                    let status = self.root_status();
                    if !status.connected || status.enabled {
                        break;
                    }
                    self.root_command(RootCommand::Enable);
                    exec::sleep_ms(10).await;
                }
                let status = self.root_status();
                if !status.enabled {
                    return Err(UsbError::NotReady);
                }
                // Real UHCI may set CSC on reset release. Acknowledge that
                // latch with PEC after enabling the still-connected port.
                if !status.connected {
                    return Err(UsbError::Disconnected);
                }
                self.root_command(RootCommand::ClearChanges);
                Ok(Some(PortSpeed::Legacy(UsbSpeed::from_ohci(
                    status.low_speed,
                ))))
            }
            #[cfg(feature = "xhci")]
            RootKind::Xhci => {
                reset_xhci(|| self.root_status(), |cmd| self.root_command(cmd), _retry)
                    .await
                    .map(|s| s.map(PortSpeed::Xhci))
            }
        }
    }

    async fn attach_legacy(&self, speed: UsbSpeed) -> Result<u8, UsbError> {
        #[cfg(test)]
        if let Some(root) = &self.test_root {
            assert!(!root.status.get().changed);
            return Ok(1);
        }
        let address = with_port_controller(self.controller, |host| {
            let (devices, next) = host.legacy_devices()?;
            if devices.iter().all(Option::is_some) {
                return None;
            }
            allocate_legacy_address(devices, next)
        })
        .flatten()
        .ok_or(UsbError::NoFreeSlots)?;
        let initial = if let Some(_hub) = self.hub.as_ref() {
            UsbDevice::new_on_hub(0, self.number, speed, _hub.address, self.number)
        } else {
            UsbDevice::new(0, self.number, speed)
        };
        let device =
            super::controller::enumerate_device(initial, address, async |device, request, data| {
                transfer().await;
                with_port_controller(self.controller, |host| {
                    host.legacy_control(device, request, data)
                })
                .ok_or(UsbError::Disconnected)
                .and_then(|result| result)
                .inspect(|_| note_startup_progress())
            })
            .await?;
        with_port_controller(self.controller, |host| {
            let (devices, _) = host.legacy_devices().ok_or(UsbError::NotSupported)?;
            *devices
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(UsbError::NoFreeSlots)? = Some(device);
            Ok(address)
        })
        .ok_or(UsbError::Disconnected)?
    }
}

impl PortOps for Port {
    async fn connection(&self) -> Result<Connection, UsbError> {
        if self.hub.is_some() {
            let (status, change) = self.hub_status().await?;
            Ok(Connection {
                connected: status & hub_port_status::CONNECTION != 0,
                changed: change & hub_port_change::C_CONNECTION != 0,
            })
        } else {
            let status = self.root_status();
            if let Some(index) = self.companion_scan {
                let mut scans = COMPANION_SCANS.borrow_mut();
                let epoch = COMPANION_HANDOFF.get();
                if scans[index] != epoch {
                    scans[index] = epoch;
                    note_startup_progress();
                }
            }
            Ok(Connection {
                connected: status.connected,
                changed: status.changed,
            })
        }
    }

    async fn clear_change(&self) -> Result<(), UsbError> {
        if self.hub.is_some() {
            self.hub_feature(request::CLEAR_FEATURE, hub_feature::C_PORT_CONNECTION)
                .await
        } else {
            self.root_command(RootCommand::ClearChanges);
            Ok(())
        }
    }

    async fn bring_up(&self, retry: bool) -> Result<Option<u8>, UsbError> {
        let shares_default_address = self.shares_default_address();
        #[cfg(test)]
        let reservation = if let Some(root) = &self.test_root {
            Some(DefaultAddress::reserve_on(root.address_zero.clone()).await)
        } else if shares_default_address {
            Some(DefaultAddress::reserve(self.controller).await)
        } else {
            None
        };
        #[cfg(not(test))]
        let reservation = if shares_default_address {
            Some(DefaultAddress::reserve(self.controller).await)
        } else {
            None
        };
        let connection = self.connection().await?;
        if !connection.connected || connection.changed {
            return Err(UsbError::Disconnected);
        }
        // Only a stable connection reaching reset is progress. A stuck
        // change latch or a bouncing connection must not renew boot forever.
        #[cfg(test)]
        let real_port = self.test_root.is_none();
        #[cfg(not(test))]
        let real_port = true;
        if real_port {
            note_startup_progress();
        }
        struct ResetGuard<'a> {
            port: &'a Port,
            reservation: Option<DefaultAddress>,
            submitted: bool,
        }
        impl Drop for ResetGuard<'_> {
            fn drop(&mut self) {
                if self.submitted
                    && let Some(reservation) = self.reservation.take()
                {
                    if let Some(hub) = &self.port.hub {
                        // Cancellation during a parked-ancestor teardown cannot
                        // issue disable requests; quarantine on the root-attached
                        // hub until physical disconnect.
                        if hub.parked() {
                            hub.root_hub().isolate_or_quarantine(
                                reservation,
                                false,
                                self.port.root_status(),
                            );
                        }
                    } else {
                        self.port.root_command(RootCommand::Disable);
                    }
                }
            }
        }
        let mut guard = ResetGuard {
            port: self,
            reservation,
            submitted: false,
        };
        let result = async {
            let Some(speed) = self.reset(retry, &mut guard.submitted).await? else {
                // If EHCI still owns the port, PO did not take effect.
                // Treat it as a failed attempt, not a new connection.
                return if self.root_status().connected {
                    Err(UsbError::NotReady)
                } else {
                    Ok(None)
                };
            };
            let link = self.connection().await?;
            if !link.connected || link.changed {
                return Err(UsbError::Disconnected);
            }
            match speed {
                PortSpeed::Legacy(speed) => self.attach_legacy(speed).await.map(Some),
                #[cfg(feature = "xhci")]
                PortSpeed::Xhci(speed) => super::xhci::enumerate::attach(
                    self.controller,
                    self.hub.as_ref().map(|hub| hub.address),
                    self.number,
                    speed,
                )
                .await
                .map(Some),
            }
        }
        .await;
        let reservation = guard.reservation.take();
        if result.is_err()
            && guard.submitted
            && let Some(reservation) = reservation
        {
            // Never release address zero on a failed reset or SET_ADDRESS
            // while this device can still answer it.
            if let Some(hub) = &self.hub {
                let _ = self
                    .hub_feature(request::CLEAR_FEATURE, hub_feature::PORT_ENABLE)
                    .await;
                let isolated = self.hub_status().await.is_ok_and(|(status, _)| {
                    status & hub_port_status::CONNECTION == 0
                        || status & hub_port_status::ENABLE == 0
                });
                hub.root_hub()
                    .isolate_or_quarantine(reservation, isolated, self.root_status());
            } else {
                self.root_command(RootCommand::Disable);
            }
        }
        result
    }

    fn observe_failed_bring_up(&self) {
        #[cfg(feature = "xhci")]
        if self.kind == RootKind::Xhci && self.hub.is_none() && !self.root_status().connected {
            STARTUP_MOVED.set(true);
            note_startup_progress();
        }
    }

    async fn attached(&self, address: u8, startup: StartupActivity<'_>) {
        let pipe = Pipe {
            controller: self.controller,
            address,
        };
        let Some(info) = super::bind_input(pipe).await else {
            return;
        };
        let storage = if info.is_mass_storage {
            super::publish_storage(pipe, true).await
        } else {
            Ok(())
        };
        if info.is_hub {
            let result = configure_hub(self, pipe).await;
            match result {
                Ok((hub, ports, delay)) => {
                    exec::sleep_ms(delay.max(100)).await;
                    let mut tasks = PortTasks::default();
                    for number in 1..=ports {
                        tasks.add(
                            Self {
                                hub: Some(hub.clone()),
                                number,
                                ..self.clone()
                            },
                            2,
                        );
                    }
                    // Each child port samples twice (one HUB_POLL_MS apart)
                    // before releasing its boot-discovery guard.
                    drop(startup);
                    tasks.run().await;
                    return;
                }
                Err(error) => {
                    log::warn!("USB hub {} could not be configured: {:?}", address, error)
                }
            }
        }
        drop(startup);
        retry_storage_probe(self, storage, async || {
            super::publish_storage(pipe, false).await
        })
        .await;
    }

    async fn detach(&self, address: u8) {
        #[cfg(feature = "xhci")]
        if self.kind == RootKind::Xhci {
            super::xhci::enumerate::detach(self.controller, address).await;
            return;
        }
        let mut removed = Vec::new();
        with_port_controller(self.controller, |host| {
            if let Some((devices, _)) = host.legacy_devices() {
                super::controller::detach_legacy_device(devices, address, &mut removed);
            }
        });
        for address in removed {
            super::unbind_device(self.controller, address);
        }
    }

    fn startup(&self) -> StartupActivity<'_> {
        StartupActivity::new(&STARTUP_ACTIVE)
    }

    fn upstream_parked(&self) -> bool {
        self.hub.as_ref().is_some_and(|hub| hub.parked())
    }

    fn report_parked(&self, error: &UsbError) {
        log::warn!(
            "USB: controller {} {}port {} gave up after {} attempts ({:?}); waiting for replug",
            self.controller,
            if self.hub.is_some() { "hub " } else { "root " },
            self.number,
            MAX_PORT_ATTEMPTS,
            error
        );
    }

    fn interval(&self) -> u64 {
        if self.hub.is_some() {
            HUB_POLL_MS
        } else {
            ROOT_POLL_MS
        }
    }
}

fn addressable_hub_ports(kind: RootKind, advertised: u8) -> u8 {
    match kind {
        // EHCI's transaction-translator port field is seven bits wide.
        RootKind::Ehci => advertised.min(127),
        #[cfg(feature = "xhci")]
        RootKind::Xhci => advertised.min(15),
        _ => advertised,
    }
}

async fn configure_hub(parent: &Port, pipe: Pipe) -> Result<(Rc<Hub>, u8, u64), UsbError> {
    #[cfg(feature = "xhci")]
    let geometry = if parent.kind == RootKind::Xhci {
        Some(super::xhci::enumerate::hub_geometry(pipe)?)
    } else {
        None
    };
    #[cfg(feature = "xhci")]
    let superspeed = geometry.is_some_and(|geometry| geometry.superspeed);
    #[cfg(not(feature = "xhci"))]
    let superspeed = false;
    let mut descriptor = [0; 12];
    let len = pipe
        .control(
            Control::descriptor(
                req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
                if superspeed {
                    0x2a
                } else {
                    super::controller::HUB_DESCRIPTOR_TYPE
                },
                0,
            ),
            Some(&mut descriptor),
        )
        .await?;
    let (ports, delay) = (
        addressable_hub_ports(parent.kind, descriptor[2]),
        u64::from(descriptor[5]) * 2,
    );
    if len < 7 || ports == 0 {
        return Err(UsbError::InvalidParameter);
    }
    #[cfg(feature = "xhci")]
    if let Some(geometry) = geometry {
        super::xhci::enumerate::configure_hub(pipe, geometry, ports).await?;
        note_startup_progress();
    }
    let hub = Rc::new(Hub {
        address: pipe.address,
        upstream: parent.hub.clone(),
        transport_failures: LocalCell::new(0),
        quarantine: Local::new(None),
        #[cfg(feature = "xhci")]
        superspeed,
    });
    for number in 1..=ports {
        let power = Port {
            number,
            hub: Some(hub.clone()),
            ..parent.clone()
        }
        .hub_feature(request::SET_FEATURE, hub_feature::PORT_POWER)
        .await;
        if power.is_ok() {
            note_startup_progress();
        }
        if matches!(power, Err(UsbError::Timeout | UsbError::Disconnected)) {
            power?;
        }
    }
    log::info!(
        "USB hub {}: {} ports, power delay {}ms",
        hub.address,
        ports,
        delay
    );
    Ok((hub, ports, delay))
}

#[cfg(feature = "xhci")]
async fn reset_xhci(
    status: impl Fn() -> RootStatus,
    command: impl Fn(RootCommand),
    force_reset: bool,
) -> Result<Option<u8>, UsbError> {
    const RX_DETECT: u8 = 5;
    const POLLING: u8 = 7;
    const RESET_MS: u64 = 150;
    const LINK_MS: u64 = 200;

    let initial = status();
    if initial.link_state == RX_DETECT {
        log::debug!("xHCI: RxDetect phantom device, skipping");
        return Err(UsbError::NotReady);
    }
    if !force_reset && initial.superspeed && initial.link_state == POLLING {
        exec::wait_for(LINK_MS, || {
            let now = status();
            !now.connected || (now.enabled && now.link_state == 0)
        })
        .await;
    } else if force_reset || !initial.enabled {
        // Disabling the previous slot does not reset the USB device's
        // address. On a retry, clear any stale completion bit first and
        // require completion of this reset (or warm reset).
        if force_reset {
            if initial.reset_done {
                command(RootCommand::AckReset);
            }
            if initial.warm_reset_done {
                command(RootCommand::AckWarmReset);
            }
        }
        command(RootCommand::Reset);
        let reset_completed = exec::wait_for(RESET_MS, || {
            let now = status();
            !now.connected || now.reset_done
        })
        .await;
        let now = status();
        if now.reset_done {
            command(RootCommand::AckReset);
        }
        let mut confirmed = reset_completed && now.reset_done;
        if now.connected
            && initial.superspeed
            && (!now.enabled || now.link_state != 0 || (force_reset && !confirmed))
        {
            command(RootCommand::WarmReset);
            let warm_completed = exec::wait_for(LINK_MS, || {
                let now = status();
                !now.connected || now.warm_reset_done
            })
            .await;
            let now = status();
            if now.warm_reset_done {
                command(RootCommand::AckWarmReset);
            }
            confirmed = confirmed || (warm_completed && now.warm_reset_done);
        }
        let now = status();
        if !now.connected {
            return Err(UsbError::Disconnected);
        }
        if force_reset && !confirmed {
            return Err(UsbError::NotReady);
        }
    }
    let now = status();
    if !now.connected {
        return Err(UsbError::Disconnected);
    }
    if !now.enabled || now.link_state != 0 {
        return Err(UsbError::NotReady);
    }
    Ok(Some(now.speed_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use core::future::Future;
    use core::task::{Context, Waker};

    struct FakePort {
        now: Cell<u64>,
        connection: Cell<Connection>,
        attempted: Cell<usize>,
        failures: Cell<usize>,
        /// Every bring-up latches a change while the device stays connected,
        /// as a real UHCI root port does when reset is released.
        reset_latches_change: bool,
        relatches_on_clear: bool,
        clear_change_fails: Cell<bool>,
        clear_change_calls: Cell<usize>,
        upstream_parked: Cell<bool>,
        failed_observations: Cell<usize>,
        reset_for: Cell<u64>,
        startup_active: LocalCell<usize>,
        children: bool,
        probe_media: bool,
        probes: Cell<usize>,
        events: RefCell<Vec<(&'static str, u8)>>,
    }

    impl Default for FakePort {
        fn default() -> Self {
            Self {
                now: Cell::default(),
                connection: Cell::default(),
                attempted: Cell::default(),
                failures: Cell::default(),
                reset_latches_change: false,
                relatches_on_clear: false,
                clear_change_fails: Cell::default(),
                clear_change_calls: Cell::default(),
                upstream_parked: Cell::default(),
                failed_observations: Cell::default(),
                reset_for: Cell::default(),
                startup_active: LocalCell::new(0),
                children: false,
                probe_media: false,
                probes: Cell::default(),
                events: RefCell::default(),
            }
        }
    }

    impl PortOps for &FakePort {
        async fn connection(&self) -> Result<Connection, UsbError> {
            if self.upstream_parked.get() {
                return Err(UsbError::NotReady);
            }
            Ok(self.connection.get())
        }
        async fn clear_change(&self) -> Result<(), UsbError> {
            self.clear_change_calls.update(|n| n + 1);
            if self.clear_change_fails.get() {
                return Err(UsbError::Stall);
            }
            self.connection.update(|mut s| {
                s.changed = self.relatches_on_clear;
                s
            });
            Ok(())
        }
        fn observe_failed_bring_up(&self) {
            self.failed_observations.update(|n| n + 1);
        }
        fn upstream_parked(&self) -> bool {
            self.upstream_parked.get()
        }
        async fn bring_up(&self, _retry: bool) -> Result<Option<u8>, UsbError> {
            self.attempted.update(|n| n + 1);
            self.sleep(self.reset_for.get()).await;
            if !self.connection.get().connected {
                return Err(UsbError::Disconnected);
            }
            if self.reset_latches_change {
                self.set(true, true);
                return Err(UsbError::Disconnected);
            }
            if self.failures.get() != 0 {
                self.failures.update(|n| n - 1);
                return Err(UsbError::NotReady);
            }
            Ok(Some(1))
        }
        async fn attached(&self, address: u8, startup: StartupActivity<'_>) {
            self.events.borrow_mut().push(("attached", address));
            drop(startup);
            if self.probe_media {
                use super::super::mass_storage::MassStorageError;
                self.probes.update(|n| n + 1);
                retry_storage_probe(self, Err(MassStorageError::NotReady), async || {
                    self.probes.update(|n| n + 1);
                    Err(MassStorageError::Usb(UsbError::Timeout))
                })
                .await;
            }
            if self.children {
                self.events.borrow_mut().push(("attached", 2));
                let _child_task = core::mem::DropGuard::new((), |()| {
                    self.events.borrow_mut().push(("cancelled", 2));
                });
                core::future::pending::<()>().await;
            }
        }
        async fn detach(&self, address: u8) {
            if self.children {
                self.events.borrow_mut().push(("detached", 2));
            }
            self.events.borrow_mut().push(("detached", address));
        }
        fn startup(&self) -> StartupActivity<'_> {
            StartupActivity::new(&self.startup_active)
        }
        fn interval(&self) -> u64 {
            ROOT_POLL_MS
        }
        async fn sleep(&self, ms: u64) {
            let deadline = self.now.get() + ms;
            poll_fn(|_| {
                if self.now.get() >= deadline {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }

    impl FakePort {
        fn set(&self, connected: bool, changed: bool) {
            self.connection.set(Connection { connected, changed });
        }

        fn advance(&self, ms: u64, mut task: core::pin::Pin<&mut impl Future<Output = ()>>) {
            self.now.update(|now| now + ms);
            assert!(
                task.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
    }

    #[test]
    fn port_task_accepts_late_first_connection_and_detaches() {
        let port = FakePort::default();
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.advance(0, task.as_mut());
        port.advance(900, task.as_mut());
        assert!(port.events.borrow().is_empty());
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
        port.set(false, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1), ("detached", 1)]);
    }

    #[test]
    fn port_task_restarts_debounce_on_latched_bounce() {
        let port = FakePort::default();
        port.set(true, true);
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.advance(0, task.as_mut());
        port.set(true, true);
        port.advance(DEBOUNCE_MS, task.as_mut());
        port.advance(DEBOUNCE_MS - 1, task.as_mut());
        assert_eq!(port.attempted.get(), 0);
        port.advance(1, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn port_tasks_pick_up_usb3_after_device_moves_during_usb2_reset() {
        let usb2 = FakePort {
            reset_for: Cell::new(70),
            ..FakePort::default()
        };
        let usb3 = FakePort::default();
        let mut old = core::pin::pin!(port_task(&usb2, 0, None));
        let mut new = core::pin::pin!(port_task(&usb3, 0, None));
        usb2.set(true, true);
        usb2.advance(0, old.as_mut());
        usb3.advance(0, new.as_mut());
        usb2.advance(DEBOUNCE_MS, old.as_mut());
        usb2.set(false, true);
        usb3.set(true, true);
        usb2.advance(70, old.as_mut());
        usb3.advance(170, new.as_mut());
        usb3.advance(DEBOUNCE_MS, new.as_mut());
        assert_eq!(usb2.attempted.get(), 1);
        assert!(usb2.events.borrow().is_empty());
        assert_eq!(*usb3.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn port_task_retries_a_device_that_returns_to_the_same_port() {
        let port = FakePort {
            reset_for: Cell::new(70),
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        port.set(false, true);
        port.advance(70, task.as_mut());
        assert!(port.events.borrow().is_empty());
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        port.advance(70, task.as_mut());
        assert_eq!(port.attempted.get(), 2);
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn port_task_retries_enumeration_without_a_new_connection() {
        let port = FakePort {
            failures: Cell::new(1),
            ..FakePort::default()
        };
        port.set(true, true);
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.advance(0, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(port.attempted.get(), 1);
        assert!(port.events.borrow().is_empty());
        port.advance(250, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(port.attempted.get(), 2);
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn hub_port_limit_depends_on_the_controller_route_format() {
        assert_eq!(addressable_hub_ports(RootKind::Ohci, 32), 32);
        assert_eq!(addressable_hub_ports(RootKind::Ehci, 32), 32);
        assert_eq!(addressable_hub_ports(RootKind::Ehci, 255), 127);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(addressable_hub_ports(RootKind::Uhci, 32), 32);
        #[cfg(feature = "xhci")]
        assert_eq!(addressable_hub_ports(RootKind::Xhci, 32), 15);
    }

    #[test]
    fn sparse_status_polls_do_not_starve_device_work() {
        let transfers = TransferBudget::new();
        let status_count = Cell::new(0);
        let bind_count = Cell::new(0);
        let mut task = core::pin::pin!(select(
            async {
                loop {
                    // Think of each poll as occurring 250 ms later: the 200 ms
                    // watcher delay has elapsed on every turn of the executor.
                    transfers.take().await;
                    status_count.update(|n| n + 1);
                    exec::yield_now().await;
                }
            },
            async {
                for _ in 0..3 {
                    transfers.take().await;
                    bind_count.update(|n| n + 1);
                    exec::yield_now().await;
                }
            }
        ));
        for _ in 0..10 {
            transfers.available.set(true);
            if task
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                break;
            }
        }
        assert_eq!(bind_count.get(), 3);
        assert!(status_count.get() >= 3);
    }

    #[test]
    fn cancelling_a_queued_transfer_unblocks_the_next_request() {
        let transfers = TransferBudget::new();
        let cx = &mut Context::from_waker(Waker::noop());
        let mut next = core::pin::pin!(transfers.take());
        {
            let mut cancelled = core::pin::pin!(transfers.take());
            assert!(cancelled.as_mut().poll(cx).is_pending());
            assert!(next.as_mut().poll(cx).is_pending());
        }
        transfers.available.set(true);
        assert!(next.as_mut().poll(cx).is_ready());
    }

    #[test]
    fn hub_transport_failures_park_the_whole_hub_until_replaced() {
        let hub = Rc::new(Hub {
            address: 1,
            upstream: None,
            transport_failures: LocalCell::new(0),
            quarantine: Local::new(None),
            #[cfg(feature = "xhci")]
            superspeed: false,
        });
        let sibling = hub.clone();
        hub.note_transport_failure();
        sibling.note_transport_failure();
        assert!(!sibling.parked());
        // A successful request clears transient failures before parking.
        hub.note_transport_success();
        hub.note_transport_failure();
        sibling.note_transport_failure();
        assert!(!hub.parked());
        // Three consecutive failures park the hub permanently.
        hub.note_transport_failure();
        assert!(hub.parked());
        hub.note_transport_success();
        assert!(hub.parked());
    }

    #[test]
    fn failed_isolation_keeps_address_zero_reserved_until_hub_detaches() {
        let owner = Rc::new(LocalCell::new(false));
        let cx = &mut Context::from_waker(Waker::noop());
        let mut next = core::pin::pin!(DefaultAddress::reserve_on(owner.clone()));
        {
            let hub = Hub {
                address: 1,
                upstream: None,
                transport_failures: LocalCell::new(0),
                quarantine: Local::new(None),
                #[cfg(feature = "xhci")]
                superspeed: false,
            };
            let reservation = exec::block_on(DefaultAddress::reserve_on(owner.clone()));
            let connected = RootStatus {
                connected: true,
                ..RootStatus::default()
            };
            hub.isolate_or_quarantine(reservation, true, connected);
            assert!(!owner.get());
            let reservation = exec::block_on(DefaultAddress::reserve_on(owner.clone()));
            hub.isolate_or_quarantine(reservation, false, RootStatus::default());
            assert!(!owner.get());
            let reservation = exec::block_on(DefaultAddress::reserve_on(owner.clone()));
            hub.isolate_or_quarantine(reservation, false, connected);
            assert!(hub.parked());
            assert!(next.as_mut().poll(cx).is_pending());
        }
        assert!(next.as_mut().poll(cx).is_ready());
    }

    #[test]
    fn boot_wait_is_capped_even_while_a_port_keeps_reporting_progress() {
        // The R500 failure: a root port reset forever, each round counted
        // as progress, and boot never left discovery.
        let mut drain = BootDrain::new(0, 0);
        let mut progress = 0;
        let mut now = 0;
        while now + 200 < BOOT_DISCOVERY_CAP_MS {
            now += 200;
            progress += 1;
            assert!(!drain.settled(now, progress, 1, true, 0));
        }
        assert!(drain.settled(BOOT_DISCOVERY_CAP_MS, progress + 1, 1, true, 0));
    }

    pub(super) struct TestRoot {
        pub(super) status: LocalCell<RootStatus>,
        pub(super) address_zero: Rc<LocalCell<bool>>,
        changes_cleared: LocalCell<u8>,
    }
    impl TestRoot {
        pub(super) fn command(&self, command: RootCommand) {
            self.status.update(|status| match command {
                RootCommand::Reset => status.enabled = false,
                RootCommand::EndReset => status.changed = true, // Real R500 behavior.
                RootCommand::Enable => status.enabled = true,
                RootCommand::ClearChanges => {
                    status.changed = false;
                    self.changes_cleared.update(|n| *n += 1);
                }
                _ => unreachable!("unexpected UHCI root command"),
            });
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn uhci_bring_up_acknowledges_csc_latched_by_end_reset() {
        let root = Rc::new(TestRoot {
            status: LocalCell::new(RootStatus {
                connected: true,
                ..RootStatus::default()
            }),
            address_zero: Rc::new(LocalCell::new(false)),
            changes_cleared: LocalCell::new(0),
        });
        let port = Port {
            controller: 0,
            kind: RootKind::Uhci,
            number: 0,
            root_number: 0,
            hub: None,
            companion_scan: None,
            test_root: Some(root.clone()),
        };
        assert!(matches!(exec::block_on(port.bring_up(false)), Ok(Some(1))));
        assert_eq!(root.changes_cleared.get(), 1);
    }

    #[test]
    fn sticky_connected_change_during_debounce_exhausts_the_same_budget() {
        let port = FakePort {
            relatches_on_clear: true,
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        assert_eq!(port.startup_active.get(), 1);
        for _ in 0..MAX_PORT_ATTEMPTS {
            port.advance(DEBOUNCE_MS, task.as_mut());
        }
        for _ in 0..10 {
            port.advance(ROOT_POLL_MS, task.as_mut());
        }
        assert_eq!(port.attempted.get(), 0);
        assert_eq!(port.startup_active.get(), 0);
    }

    #[test]
    fn boot_cap_counts_the_first_connection_wait() {
        let mut drain = BootDrain::new(0, 0);
        drain.last_ms = CONNECTION_TIMEOUT_MS;
        assert!(!drain.settled(BOOT_DISCOVERY_CAP_MS - 1, 1, 1, true, 0));
        assert!(drain.settled(BOOT_DISCOVERY_CAP_MS, 2, 1, true, 0));
    }

    #[test]
    fn port_task_does_not_restart_forever_on_a_change_it_caused() {
        let port = FakePort {
            reset_latches_change: true,
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        for _ in 0..200 {
            port.advance(50, task.as_mut());
        }
        // Three attempts for this attachment, then parked until replug.
        assert_eq!(port.attempted.get(), MAX_PORT_ATTEMPTS);
        assert_eq!(port.startup_active.get(), 0);
        assert!(port.events.borrow().is_empty());
    }

    #[test]
    fn boot_drains_a_slow_device_while_it_is_making_progress() {
        let mut drain = BootDrain::new(0, 0);
        for (step, now) in [500, 1100, 1700, 2300].into_iter().enumerate() {
            assert!(!drain.settled(now, step as u64 + 1, 1, true, 0));
        }
        assert!(drain.settled(2500, 5, 0, true, 0));
    }

    #[test]
    fn boot_waits_through_the_gap_after_ehci_handoff() {
        let mut drain = BootDrain::new(0, 0);
        assert!(!drain.settled(300, 1, 0, false, 50));
        assert!(!drain.settled(325, 2, 1, true, 50));
        assert!(!drain.settled(500, 3, 0, true, 50));
        assert!(drain.settled(550, 3, 0, true, 50));
    }

    #[test]
    fn boot_can_leave_a_dead_device_without_progress() {
        let mut drain = BootDrain::new(0, 0);
        assert!(!drain.settled(100, 1, 1, true, 0));
        assert!(!drain.settled(1099, 1, 1, true, 0));
        assert!(drain.settled(1100, 1, 1, true, 0));
    }

    #[test]
    fn no_activity_adds_no_drain_wait_after_initial_window() {
        let mut drain = BootDrain::new(1000, 0);
        assert!(drain.settled(1000, 0, 0, true, 0));
    }

    #[test]
    fn first_port_wait_ends_at_activity_or_the_deadline() {
        // No real clock: hold the deadline pending while the port starts,
        // then test the opposite case with the deadline already ready.
        let started = Cell::new(false);
        let mut wait =
            core::pin::pin!(wait_for_first_port(core::future::pending(), || started.get()));
        let cx = &mut Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(cx).is_pending());
        started.set(true);
        assert!(wait.as_mut().poll(cx).is_ready());
        let mut wait = core::pin::pin!(wait_for_first_port(core::future::ready(()), || false));
        assert!(wait.as_mut().poll(cx).is_ready());
    }

    #[test]
    fn port_task_exhausts_attempts_then_retries_only_after_reconnect() {
        let port = FakePort {
            failures: Cell::new(MAX_PORT_ATTEMPTS),
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        for attempt in 1..=MAX_PORT_ATTEMPTS {
            port.advance(DEBOUNCE_MS, task.as_mut());
            assert_eq!(port.attempted.get(), attempt);
            if attempt != MAX_PORT_ATTEMPTS {
                port.advance(PORT_RETRY_MS, task.as_mut());
            }
        }
        for _ in 0..5 {
            port.advance(1000, task.as_mut());
        }
        assert_eq!(port.attempted.get(), MAX_PORT_ATTEMPTS);
        assert!(port.events.borrow().is_empty());
        port.set(false, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn storage_probe_retries_not_ready_but_stops_on_transport_failure_until_reconnect() {
        let port = FakePort {
            probe_media: true,
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(port.probes.get(), 1);
        port.advance(CONNECTION_TIMEOUT_MS, task.as_mut());
        port.advance(10 * CONNECTION_TIMEOUT_MS, task.as_mut());
        assert_eq!(port.probes.get(), 2);
        port.set(false, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(port.probes.get(), 3);
        port.advance(CONNECTION_TIMEOUT_MS, task.as_mut());
        assert_eq!(port.probes.get(), 4);
    }

    #[test]
    fn port_task_detaches_hub_tree_on_disconnect() {
        let port = FakePort {
            children: true,
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        port.set(false, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        assert_eq!(
            *port.events.borrow(),
            [
                ("attached", 1),
                ("attached", 2),
                ("cancelled", 2),
                ("detached", 2),
                ("detached", 1)
            ]
        );
    }

    #[cfg(feature = "xhci")]
    #[test]
    fn xhci_retry_resets_an_enabled_u0_device() {
        let status = Cell::new(RootStatus {
            connected: true,
            enabled: true,
            superspeed: true,
            speed_id: 4,
            ..RootStatus::default()
        });
        let resets = Cell::new(0);
        assert!(matches!(
            exec::block_on(reset_xhci(
                || status.get(),
                |cmd| {
                    if matches!(cmd, RootCommand::Reset) {
                        resets.set(resets.get() + 1);
                        status.update(|mut s| {
                            s.reset_done = true;
                            s
                        });
                    }
                },
                true
            )),
            Ok(Some(4))
        ));
        assert_eq!(resets.get(), 1);
    }

    #[cfg(feature = "xhci")]
    #[test]
    fn reset_xhci_uses_warm_reset_when_usb3_link_stays_down() {
        let status = Cell::new(RootStatus {
            connected: true,
            superspeed: true,
            speed_id: 4,
            link_state: 3,
            ..RootStatus::default()
        });
        let speed = exec::block_on(reset_xhci(
            || status.get(),
            |command| {
                status.update(|mut status| {
                    match command {
                        RootCommand::Reset => status.reset_done = true,
                        RootCommand::AckReset => status.reset_done = false,
                        RootCommand::WarmReset => {
                            status.warm_reset_done = true;
                            status.link_state = 0;
                            status.enabled = true;
                        }
                        RootCommand::AckWarmReset => status.warm_reset_done = false,
                        _ => panic!("unexpected root command"),
                    }
                    status
                });
            },
            false,
        ))
        .unwrap();
        assert_eq!(speed, Some(4));
        assert!(!status.get().warm_reset_done);
    }

    #[cfg(feature = "xhci")]
    #[test]
    fn reset_xhci_skips_rx_detect_phantom_device() {
        let status = RootStatus {
            connected: true,
            link_state: 5,
            ..RootStatus::default()
        };
        assert!(matches!(
            exec::block_on(reset_xhci(
                || status,
                |_| panic!("must not reset phantom device"),
                false
            )),
            Err(UsbError::NotReady)
        ));
    }

    #[cfg(feature = "xhci")]
    #[test]
    fn xhci_forced_reset_fails_when_u0_never_completes_reset() {
        // Stale PRC is cleared before Reset; without a new PRC, forced reset
        // must fail even though the link stays enabled in U0.
        let status = Cell::new(RootStatus {
            connected: true,
            enabled: true,
            reset_done: true,
            speed_id: 3,
            ..RootStatus::default()
        });
        let acks = Cell::new(0);
        let resets = Cell::new(0);
        let result = exec::block_on(reset_xhci(
            || status.get(),
            |cmd| {
                status.update(|mut s| {
                    match cmd {
                        RootCommand::AckReset => {
                            acks.set(acks.get() + 1);
                            s.reset_done = false;
                        }
                        RootCommand::Reset => {
                            resets.set(resets.get() + 1);
                        }
                        _ => panic!("unexpected command"),
                    }
                    s
                });
            },
            true,
        ));
        assert!(matches!(result, Err(UsbError::NotReady)));
        assert_eq!(acks.get(), 1);
        assert_eq!(resets.get(), 1);
    }

    #[test]
    fn hub_child_keeps_startup_active_across_second_post_power_sample() {
        let port = FakePort::default();
        let initial = Some(StartupActivity::new(&port.startup_active));
        let mut task = core::pin::pin!(port_task(&port, 2, initial));
        let mut drain = BootDrain::new(0, 0);
        // Sample 1: disconnected, must keep startup active until sample 2.
        port.advance(0, task.as_mut());
        assert_eq!(port.startup_active.get(), 1);
        assert!(!drain.settled(0, 1, port.startup_active.get(), true, 0));
        // Device connects between sample 1 and sample 2.
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        assert_eq!(port.startup_active.get(), 1);
        assert!(!drain.settled(ROOT_POLL_MS, 1, port.startup_active.get(), true, 0));
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
        assert_eq!(port.startup_active.get(), 0);
        assert!(drain.settled(
            ROOT_POLL_MS + DEBOUNCE_MS,
            2,
            port.startup_active.get(),
            true,
            0
        ));
    }

    #[test]
    fn attached_child_detaches_when_upstream_hub_is_parked() {
        let port = FakePort::default();
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
        port.upstream_parked.set(true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1), ("detached", 1)]);
    }

    #[test]
    fn stalled_clear_change_parks_port_within_retry_budget() {
        let port = FakePort::default();
        port.clear_change_fails.set(true);
        port.set(true, true);
        let initial = Some(StartupActivity::new(&port.startup_active));
        let mut task = core::pin::pin!(port_task(&port, 2, initial));
        for _ in 0..MAX_PORT_ATTEMPTS {
            port.advance(ROOT_POLL_MS, task.as_mut());
        }
        assert_eq!(port.startup_active.get(), 0);
        assert_eq!(port.attempted.get(), 0);
    }

    #[test]
    fn exhausted_port_wakes_on_replug_between_polls() {
        let port = FakePort {
            failures: Cell::new(MAX_PORT_ATTEMPTS),
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        for attempt in 1..=MAX_PORT_ATTEMPTS {
            port.advance(DEBOUNCE_MS, task.as_mut());
            assert_eq!(port.attempted.get(), attempt);
            if attempt != MAX_PORT_ATTEMPTS {
                port.advance(PORT_RETRY_MS, task.as_mut());
            }
        }
        // Swap bad device for good device between polls (connected=true, changed=true).
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(*port.events.borrow(), [("attached", 1)]);
    }

    #[test]
    fn debounce_disconnect_notifies_migration_observer() {
        let port = FakePort::default();
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        port.set(false, true);
        port.advance(DEBOUNCE_MS, task.as_mut());
        assert_eq!(port.failed_observations.get(), 1);
    }

    #[test]
    fn disconnected_stuck_change_latch_stays_parked_after_clear_failures() {
        let port = FakePort::default();
        port.clear_change_fails.set(true);
        port.set(false, true);
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        for _ in 0..MAX_PORT_ATTEMPTS {
            port.advance(ROOT_POLL_MS, task.as_mut());
        }
        assert_eq!(port.clear_change_calls.get(), MAX_PORT_ATTEMPTS);
        // Subsequent polls with the same disconnected+changed state must not retry clear_change.
        for _ in 0..10 {
            port.advance(ROOT_POLL_MS, task.as_mut());
        }
        assert_eq!(port.clear_change_calls.get(), MAX_PORT_ATTEMPTS);
    }

    #[test]
    fn fast_replug_after_verified_clear_wakes_exhausted_port() {
        let port = FakePort {
            reset_latches_change: true,
            ..FakePort::default()
        };
        let mut task = core::pin::pin!(port_task(&port, 0, None));
        port.set(true, true);
        port.advance(0, task.as_mut());
        for attempt in 1..=MAX_PORT_ATTEMPTS {
            port.advance(DEBOUNCE_MS, task.as_mut());
            assert_eq!(port.attempted.get(), attempt);
            if attempt != MAX_PORT_ATTEMPTS {
                port.advance(PORT_RETRY_MS, task.as_mut());
            }
        }
        // Final attempt saw changed=true and verified clear_change cleared it.
        // A fast replug arriving BEFORE the first parked poll must wake immediately.
        port.set(true, true);
        port.advance(ROOT_POLL_MS, task.as_mut());
        assert_eq!(port.startup_active.get(), 1);
    }

    #[test]
    fn nested_hub_root_quarantine_survives_child_hub_drop() {
        let owner = Rc::new(LocalCell::new(false));
        let cx = &mut Context::from_waker(Waker::noop());
        let mut next = core::pin::pin!(DefaultAddress::reserve_on(owner.clone()));
        let root_hub = Rc::new(Hub {
            address: 1,
            upstream: None,
            transport_failures: LocalCell::new(0),
            quarantine: Local::new(None),
            #[cfg(feature = "xhci")]
            superspeed: false,
        });
        {
            let nested_hub = Rc::new(Hub {
                address: 2,
                upstream: Some(root_hub.clone()),
                transport_failures: LocalCell::new(0),
                quarantine: Local::new(None),
                #[cfg(feature = "xhci")]
                superspeed: false,
            });
            let reservation = exec::block_on(DefaultAddress::reserve_on(owner.clone()));
            let connected = RootStatus {
                connected: true,
                ..RootStatus::default()
            };
            // Quarantining on root_hub() survives nested_hub being dropped.
            nested_hub
                .root_hub()
                .isolate_or_quarantine(reservation, false, connected);
        }
        assert!(root_hub.parked());
        assert!(next.as_mut().poll(cx).is_pending());
        drop(root_hub);
        assert!(next.as_mut().poll(cx).is_ready());
    }
}
