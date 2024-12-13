// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implementation of an admin or IO queue pair.

use super::spec;
use crate::page_allocator::PageAllocator;
use crate::page_allocator::ScopedPages;
use crate::queues::CompletionQueue;
use crate::queues::SubmissionQueue;
use crate::registers::DeviceRegisters;
use anyhow::Context;
use futures::StreamExt;
use guestmem::ranges::PagedRange;
use guestmem::GuestMemory;
use guestmem::GuestMemoryError;
use hvdef::HvError;
use inspect::Inspect;
use inspect_counters::Counter;
use mesh::rpc::Rpc;
use mesh::rpc::RpcSend;
use mesh::Cancel;
use mesh::CancelContext;
use pal_async::driver::SpawnDriver;
use pal_async::task::Task;
use safeatomic::AtomicSliceOps;
use slab::Slab;
use std::future::poll_fn;
use std::num::Wrapping;
use std::sync::Arc;
use std::task::Poll;
use thiserror::Error;
use user_driver::interrupt::DeviceInterrupt;
use user_driver::memory::MemoryBlock;
use user_driver::memory::PAGE_SIZE;
use user_driver::memory::PAGE_SIZE64;
use user_driver::DeviceBacking;
use user_driver::HostDmaAllocator;
use virt_mshv_vtl::UhPartition;
use zerocopy::FromZeroes;

/// Value for unused PRP entries, to catch/mitigate buffer size mismatches.
const INVALID_PAGE_ADDR: u64 = !(PAGE_SIZE as u64 - 1);

pub(crate) struct QueuePair {
    task: Task<QueueHandler>,
    cancel: Cancel,
    issuer: Arc<Issuer>,
    mem: MemoryBlock,
}

impl Inspect for QueuePair {
    fn inspect(&self, req: inspect::Request<'_>) {
        let Self {
            task: _,
            cancel: _,
            issuer,
            mem: _,
        } = self;
        issuer.send.send(Req::Inspect(req.defer()));
    }
}

impl PendingCommands {
    const CID_KEY_BITS: u32 = 10;
    const CID_KEY_MASK: u16 = (1 << Self::CID_KEY_BITS) - 1;
    const MAX_CIDS: usize = 1 << Self::CID_KEY_BITS;
    const CID_SEQ_OFFSET: Wrapping<u16> = Wrapping(1 << Self::CID_KEY_BITS);

    fn new() -> Self {
        Self {
            commands: Slab::new(),
            next_cid_high_bits: Wrapping(0),
        }
    }

    fn is_full(&self) -> bool {
        self.commands.len() >= Self::MAX_CIDS
    }

    fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Inserts a command into the pending list, updating it with a new CID.
    fn insert(
        &mut self,
        command: &mut spec::Command,
        respond: mesh::OneshotSender<spec::Completion>,
    ) {
        let entry = self.commands.vacant_entry();
        assert!(entry.key() < Self::MAX_CIDS);
        assert_eq!(self.next_cid_high_bits % Self::CID_SEQ_OFFSET, Wrapping(0));
        let cid = entry.key() as u16 | self.next_cid_high_bits.0;
        self.next_cid_high_bits += Self::CID_SEQ_OFFSET;
        command.cdw0.set_cid(cid);
        entry.insert(PendingCommand {
            command: *command,
            respond,
        });
    }

    fn remove(&mut self, cid: u16) -> mesh::OneshotSender<spec::Completion> {
        let command = self
            .commands
            .try_remove((cid & Self::CID_KEY_MASK) as usize)
            .expect("completion for unknown cid");
        assert_eq!(
            command.command.cdw0.cid(),
            cid,
            "cid sequence number mismatch"
        );
        command.respond
    }
}

impl QueuePair {
    pub const MAX_SQSIZE: u16 = (PAGE_SIZE / 64) as u16; // Maximum SQ size in entries.
    pub const MAX_CQSIZE: u16 = (PAGE_SIZE / 16) as u16; // Maximum CQ size in entries.

    pub fn new(
        spawner: impl SpawnDriver,
        device: &impl DeviceBacking,
        qid: u16,
        sq_size: u16,
        cq_size: u16,
        mut interrupt: DeviceInterrupt,
        registers: Arc<DeviceRegisters<impl DeviceBacking>>,
        bounce_buffer_pages: u64,
        io_threshold: Option<u32>,
        partition: Option<Arc<UhPartition>>,
    ) -> anyhow::Result<Self> {
        let mem = device
            .host_allocator()
            .allocate_dma_buffer(PAGE_SIZE * 2)
            .context("failed to allocate memory for queues")?;

        assert!(sq_size <= Self::MAX_SQSIZE);
        assert!(cq_size <= Self::MAX_CQSIZE);

        let sq = SubmissionQueue::new(qid, sq_size, mem.subblock(0, PAGE_SIZE));
        let cq = CompletionQueue::new(qid, cq_size, mem.subblock(PAGE_SIZE, PAGE_SIZE));

        let (send, recv) = mesh::channel();
        let (mut ctx, cancel) = CancelContext::new().with_cancel();
        let mut queue_handler = QueueHandler {
            sq,
            cq,
            commands: PendingCommands::new(),
            stats: Default::default(),
        };
        let task = spawner.spawn("nvme-queue", {
            async move {
                ctx.until_cancelled(async {
                    queue_handler.run(&registers, recv, &mut interrupt).await;
                })
                .await
                .ok();
                queue_handler
            }
        });

        // caller ensure the bounce_buffer_pages
        const MIN_PER_QUEUE_PAGES: usize = (512 * 1024 + PAGE_SIZE) / PAGE_SIZE;
        let buffer_size_pages = std::cmp::max(bounce_buffer_pages as usize, MIN_PER_QUEUE_PAGES);
        let alloc = PageAllocator::new(
            device
                .host_allocator()
                .allocate_dma_buffer(buffer_size_pages * PAGE_SIZE)
                .context("failed to allocate pages for queue requests")?,
        );

        tracing::info!(qid, buffer_size_pages, "creating queue pair end");
        Ok(Self {
            task,
            cancel,
            issuer: Arc::new(Issuer {
                send,
                alloc,
                io_threshold,
                partition,
            }),
            mem,
        })
    }

    pub fn sq_addr(&self) -> u64 {
        self.mem.pfns()[0] * PAGE_SIZE64
    }

    pub fn cq_addr(&self) -> u64 {
        self.mem.pfns()[1] * PAGE_SIZE64
    }

    pub fn issuer(&self) -> &Arc<Issuer> {
        &self.issuer
    }

    pub async fn shutdown(mut self) -> impl Send {
        self.cancel.cancel();
        self.task.await
    }
}

/// An error issuing an NVMe request.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum RequestError {
    #[error("queue pair is gone")]
    Gone(#[source] mesh::RecvError),
    #[error("nvme error")]
    Nvme(#[source] NvmeError),
    #[error("memory error")]
    Memory(#[source] GuestMemoryError),
    #[error("i/o too large for double buffering")]
    TooLarge,
    #[error("hv error")]
    Hv(#[source] HvError),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NvmeError(spec::Status);

impl NvmeError {
    pub fn status(&self) -> spec::Status {
        self.0
    }
}

impl From<spec::Status> for NvmeError {
    fn from(value: spec::Status) -> Self {
        Self(value)
    }
}

impl std::error::Error for NvmeError {}

impl std::fmt::Display for NvmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.status_code_type() {
            spec::StatusCodeType::GENERIC => write!(f, "general error {:#x?}", self.0),
            spec::StatusCodeType::COMMAND_SPECIFIC => {
                write!(f, "command-specific error {:#x?}", self.0)
            }
            spec::StatusCodeType::MEDIA_ERROR => {
                write!(f, "media error {:#x?}", self.0)
            }
            _ => write!(f, "{:#x?}", self.0),
        }
    }
}

#[derive(Inspect)]
pub struct Issuer {
    #[inspect(skip)]
    send: mesh::Sender<Req>,
    alloc: PageAllocator,
    io_threshold: Option<u32>,
    #[inspect(skip)]
    partition: Option<Arc<UhPartition>>,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("send", &self.send)
            .field("alloc", &self.alloc)
            .field("io_threshold", &self.io_threshold)
            .finish()
    }
}

impl Issuer {
    pub async fn issue_raw(
        &self,
        command: spec::Command,
    ) -> Result<spec::Completion, RequestError> {
        match self.send.call(Req::Command, command).await {
            Ok(completion) if completion.status.status() == 0 => Ok(completion),
            Ok(completion) => Err(RequestError::Nvme(NvmeError(spec::Status(
                completion.status.status(),
            )))),
            Err(err) => Err(RequestError::Gone(err)),
        }
    }

    pub async fn issue_external(
        &self,
        mut command: spec::Command,
        guest_memory: &GuestMemory,
        mem: PagedRange<'_>,
    ) -> Result<spec::Completion, RequestError> {
        let mut double_buffer_pages = None;
        let opcode = spec::Opcode(command.cdw0.opcode());
        assert!(
            opcode.transfer_controller_to_host()
                || opcode.transfer_host_to_controller()
                || mem.is_empty()
        );

        // Ensure the memory is currently mapped.
        guest_memory
            .probe_gpns(mem.gpns())
            .map_err(RequestError::Memory)?;

        // TODO: add check if the memeory if VA-backed.
        let is_va_backed = true;
        let (prp, is_memory_pinned) = if !is_va_backed
            && mem
                .gpns()
                .iter()
                .all(|&gpn| guest_memory.iova(gpn * PAGE_SIZE64).is_some())
        {
            tracelimit::info_ratelimited!(
                opcode = opcode.0,
                size = mem.len(),
                is_va_backed,
                "issue io directly"
            );
            // Guest memory is available to the device, so issue the IO directly.
            (
                self.make_prp(
                    mem.offset() as u64,
                    mem.gpns()
                        .iter()
                        .map(|&gpn| guest_memory.iova(gpn * PAGE_SIZE64).unwrap()),
                )
                .await,
                false,
            )
        } else {
            // Guest memory is not accessible by the device.
            // If guest memory is VA-backed, and IO size exceeds threshold, pin the memory.
            let mut prp_result = None;
            let mut is_pinned = false;
            if let Some(io_threshold) = self.io_threshold {
                if is_va_backed && self.partition.is_some() && mem.len() as u32 > io_threshold {
                    tracelimit::info_ratelimited!(
                        opcode = opcode.0,
                        size = mem.len(),
                        is_va_backed,
                        "pin guest memory"
                    );
                    self.partition
                        .as_ref()
                        .unwrap()
                        .pin_gpa_ranges(&mem.memoryranges())
                        .map_err(RequestError::Hv)?;
                    is_pinned = true;
                    prp_result = Some(
                        self.make_prp(
                            mem.offset() as u64,
                            mem.gpns()
                                .iter()
                                .map(|&gpn| guest_memory.iova(gpn * PAGE_SIZE64).unwrap()),
                        )
                        .await,
                    );
                }
            }

            if prp_result.is_none() {
                // Guest memory is not accessible by the device. Double buffer through an allocation.
                prp_result = match self.alloc.alloc_bytes(mem.len()).await {
                    Some(pages) => {
                        tracelimit::info_ratelimited!(
                            opcode = opcode.0,
                            size = mem.len(),
                            is_va_backed,
                            "double buffering"
                        );
                        let double_buffer_pages = double_buffer_pages.insert(pages);
                        if opcode.transfer_host_to_controller() {
                            double_buffer_pages
                                .copy_from_guest_memory(guest_memory, mem)
                                .map_err(RequestError::Memory)?;
                        }
                        Some(
                            self.make_prp(
                                0,
                                (0..double_buffer_pages.page_count())
                                    .map(|i| double_buffer_pages.physical_address(i)),
                            )
                            .await,
                        )
                    }
                    None => {
                        // Allocation failed. If guest memory is VA-backed, pin the memory. Otherwise return error.
                        if is_va_backed && self.partition.is_some() {
                            tracelimit::info_ratelimited!(
                                opcode = opcode.0,
                                size = mem.len(),
                                is_va_backed,
                                "pin guest memory after allocation failed"
                            );
                            self.partition
                                .as_ref()
                                .unwrap()
                                .pin_gpa_ranges(&mem.memoryranges())
                                .map_err(RequestError::Hv)?;
                            is_pinned = true;
                            Some(
                                self.make_prp(
                                    mem.offset() as u64,
                                    mem.gpns()
                                        .iter()
                                        .map(|&gpn| guest_memory.iova(gpn * PAGE_SIZE64).unwrap()),
                                )
                                .await,
                            )
                        } else {
                            return Err(RequestError::TooLarge);
                        }
                    }
                }
            }

            (prp_result.unwrap(), is_pinned)
        };

        command.dptr = prp.dptr;
        let r = self.issue_raw(command).await;
        if let Some(double_buffer_pages) = double_buffer_pages {
            if r.is_ok() && opcode.transfer_controller_to_host() {
                double_buffer_pages
                    .copy_to_guest_memory(guest_memory, mem)
                    .map_err(RequestError::Memory)?;
            }
        }

        if is_memory_pinned {
            self.partition
                .as_ref()
                .unwrap()
                .unpin_gpa_ranges(&mem.memoryranges())
                .map_err(RequestError::Hv)?;
        }
        r
    }

    async fn make_prp(
        &self,
        offset: u64,
        mut iovas: impl ExactSizeIterator<Item = u64>,
    ) -> Prp<'_> {
        let mut prp_pages = None;
        let dptr = match iovas.len() {
            0 => [INVALID_PAGE_ADDR; 2],
            1 => [iovas.next().unwrap() + offset, INVALID_PAGE_ADDR],
            2 => [iovas.next().unwrap() + offset, iovas.next().unwrap()],
            _ => {
                let a = iovas.next().unwrap();
                assert!(iovas.len() <= 4096);
                let prp = self
                    .alloc
                    .alloc_pages(1)
                    .await
                    .expect("pool cap is >= 1 page");

                let prp_addr = prp.physical_address(0);
                let page = prp.page_as_slice(0);
                for (iova, dest) in iovas.zip(page.chunks_exact(8)) {
                    dest.atomic_write_obj(&iova.to_le_bytes());
                }
                prp_pages = Some(prp);
                [a + offset, prp_addr]
            }
        };
        Prp {
            dptr,
            _pages: prp_pages,
        }
    }

    pub async fn issue_neither(
        &self,
        mut command: spec::Command,
    ) -> Result<spec::Completion, RequestError> {
        command.dptr = [INVALID_PAGE_ADDR; 2];
        self.issue_raw(command).await
    }

    pub async fn issue_in(
        &self,
        mut command: spec::Command,
        data: &[u8],
    ) -> Result<spec::Completion, RequestError> {
        let mem = self
            .alloc
            .alloc_bytes(data.len())
            .await
            .expect("pool cap is >= 1 page");

        mem.write(data);
        let prp = mem.prp();
        command.dptr = prp.dptr;
        self.issue_raw(command).await
    }

    pub async fn issue_out(
        &self,
        mut command: spec::Command,
        data: &mut [u8],
    ) -> Result<spec::Completion, RequestError> {
        let mem = self
            .alloc
            .alloc_bytes(data.len())
            .await
            .expect("pool cap is sufficient");

        let prp = mem.prp();
        command.dptr = prp.dptr;
        let completion = self.issue_raw(command).await;
        mem.read(data);
        completion
    }
}

impl ScopedPages<'_> {
    fn prp(&self) -> Prp<'_> {
        assert_eq!(
            self.page_count(),
            1,
            "larger requests not currently supported"
        );
        Prp {
            dptr: [self.physical_address(0), INVALID_PAGE_ADDR],
            _pages: None,
        }
    }
}

struct Prp<'a> {
    dptr: [u64; 2],
    _pages: Option<ScopedPages<'a>>,
}

#[derive(Inspect)]
struct PendingCommands {
    /// Mapping from the low bits of cid to pending command.
    #[inspect(iter_by_key)]
    commands: Slab<PendingCommand>,
    #[inspect(hex)]
    next_cid_high_bits: Wrapping<u16>,
}

#[derive(Inspect)]
struct PendingCommand {
    // Keep the command around for diagnostics.
    command: spec::Command,
    #[inspect(skip)]
    respond: mesh::OneshotSender<spec::Completion>,
}

enum Req {
    Command(Rpc<spec::Command, spec::Completion>),
    Inspect(inspect::Deferred),
}

#[derive(Inspect)]
struct QueueHandler {
    sq: SubmissionQueue,
    cq: CompletionQueue,
    commands: PendingCommands,
    stats: QueueStats,
}

#[derive(Inspect, Default)]
struct QueueStats {
    issued: Counter,
    completed: Counter,
    interrupts: Counter,
}

impl QueueHandler {
    async fn run(
        &mut self,
        registers: &DeviceRegisters<impl DeviceBacking>,
        mut recv: mesh::Receiver<Req>,
        interrupt: &mut DeviceInterrupt,
    ) {
        loop {
            enum Event {
                Request(Req),
                Completion(spec::Completion),
            }

            let event = poll_fn(|cx| {
                if !self.sq.is_full() && !self.commands.is_full() {
                    if let Poll::Ready(Some(req)) = recv.poll_next_unpin(cx) {
                        return Event::Request(req).into();
                    }
                }
                while !self.commands.is_empty() {
                    if let Some(completion) = self.cq.read() {
                        return Event::Completion(completion).into();
                    }
                    if interrupt.poll(cx).is_pending() {
                        break;
                    }
                    self.stats.interrupts.increment();
                }
                self.sq.commit(registers);
                self.cq.commit(registers);
                Poll::Pending
            })
            .await;

            match event {
                Event::Request(req) => match req {
                    Req::Command(Rpc(mut command, respond)) => {
                        self.commands.insert(&mut command, respond);
                        self.sq.write(command).unwrap();
                        self.stats.issued.increment();
                    }
                    Req::Inspect(deferred) => deferred.inspect(&self),
                },
                Event::Completion(completion) => {
                    assert_eq!(completion.sqid, self.sq.id());
                    let respond = self.commands.remove(completion.cid);
                    self.sq.update_head(completion.sqhd);
                    respond.send(completion);
                    self.stats.completed.increment();
                }
            }
        }
    }
}

pub(crate) fn admin_cmd(opcode: spec::AdminOpcode) -> spec::Command {
    spec::Command {
        cdw0: spec::Cdw0::new().with_opcode(opcode.0),
        ..FromZeroes::new_zeroed()
    }
}
