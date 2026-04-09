// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides access to storvsc driver instances shared between disks on each
//! vStor controller.
//!
//! Manages shared StorvscDriver instances (one per VMBus SCSI controller),
//! following the same actor-based pattern as NvmeManager. Each driver is
//! created on first use and shared across all disks (LUNs) on that controller.
//!
//! The manager also owns the per-LUN StorvscDisk cache. During servicing,
//! it saves live disk metadata (read from AtomicU64 fields -- always fresh)
//! and restores disks without SCSI queries on the restore path.

use crate::servicing::StorvscSavedState;
use crate::storvsc_manager::save_restore::StorvscManagerSavedState;
use crate::storvsc_manager::save_restore::StorvscSavedDiskMetadata;
use crate::storvsc_manager::save_restore::StorvscSavedDriverConfig;
use anyhow::Context;
use async_trait::async_trait;
use disk_backend::resolve::ResolveDiskParameters;
use disk_backend::resolve::ResolvedDisk;
use futures::StreamExt;
use futures::TryFutureExt;
use futures::future::join_all;
use inspect::Inspect;
use mesh::MeshPayload;
use mesh::rpc::Rpc;
use mesh::rpc::RpcSend;
use openhcl_dma_manager::AllocationVisibility;
use openhcl_dma_manager::DmaClientParameters;
use openhcl_dma_manager::DmaClientSpawner;
use openhcl_dma_manager::LowerVtlPermissionPolicy;
use pal_async::task::Spawn;
use pal_async::task::Task;
use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::Arc;
use storvsc_driver::StorvscDriver;
use tracing::Instrument;
use vm_resource::AsyncResolveResource;
use vm_resource::ResourceId;
use vm_resource::ResourceResolver;
use vm_resource::kind::DiskHandleKind;
use vmbus_user_channel::MappedRingMem;
use vmcore::vm_task::VmTaskDriverSource;

const STORVSC_IN_RING_SIZE: usize = 0x1ff000;
const STORVSC_OUT_RING_SIZE: usize = 0x1ff000;

#[derive(Debug, thiserror::Error)]
enum InnerError {
    #[error("failed to initialize vmbus channel")]
    Vmbus(#[source] vmbus_user_channel::Error),
    #[error("failed to initialize storvsc driver")]
    DriverInitFailed(#[source] storvsc_driver::StorvscError),
    #[error("failed to create dma client for device")]
    DmaClient(#[source] anyhow::Error),
}

#[derive(Debug)]
pub struct StorvscManager {
    task: Task<()>,
    client: StorvscManagerClient,
    /// Running environment (memory layout) supports save/restore.
    save_restore_supported: bool,
}

impl Inspect for StorvscManager {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.merge(inspect::adhoc(|req| {
            self.client.sender.send(Request::Inspect(req.defer()))
        }));
    }
}

impl StorvscManager {
    pub fn new(
        driver_source: &VmTaskDriverSource,
        save_restore_supported: bool,
        is_isolated: bool,
        saved_state: Option<StorvscSavedState>,
        dma_client_spawner: DmaClientSpawner,
    ) -> Self {
        let (send, recv) = mesh::channel();
        let driver = driver_source.simple();
        let mut worker = StorvscManagerWorker {
            driver_source: driver_source.clone(),
            drivers: HashMap::new(),
            disks: HashMap::new(),
            saved_disk_metadata: HashMap::new(),
            save_restore_supported,
            is_isolated,
            dma_client_spawner,
        };
        let task = driver.spawn("storvsc-manager", async move {
            // Restore saved data (if present) before async worker thread runs.
            if let Some(s) = saved_state.as_ref() {
                if let Err(e) = StorvscManager::restore(&mut worker, s)
                    .instrument(tracing::info_span!("storvsc_manager_restore"))
                    .await
                {
                    tracing::error!(
                        error = e.as_ref() as &dyn std::error::Error,
                        "failed to restore storvsc manager"
                    );
                }
            };
            worker.run(recv).await
        });
        Self {
            task,
            client: StorvscManagerClient { sender: send },
            save_restore_supported,
        }
    }

    pub fn client(&self) -> &StorvscManagerClient {
        &self.client
    }

    pub async fn shutdown(self) {
        self.client.sender.send(Request::Shutdown {
            span: tracing::info_span!("shutdown_storvsc_manager"),
        });
        self.task.await;
    }

    /// Save storvsc manager state during servicing.
    pub async fn save(&self) -> Option<StorvscManagerSavedState> {
        if self.save_restore_supported {
            Some(self.client().save().await?)
        } else {
            None
        }
    }

    /// Restore the storvsc manager state after servicing.
    async fn restore(
        worker: &mut StorvscManagerWorker,
        saved_state: &StorvscSavedState,
    ) -> anyhow::Result<()> {
        worker
            .restore(&saved_state.storvsc_state)
            .instrument(tracing::info_span!("storvsc_worker_restore"))
            .await?;

        Ok(())
    }
}

enum Request {
    Inspect(inspect::Deferred),
    GetOrCreateDisk(Rpc<(guid::Guid, u8), Result<Arc<disk_storvsc::StorvscDisk>, anyhow::Error>>),
    Save(Rpc<(), Result<StorvscManagerSavedState, anyhow::Error>>),
    Shutdown { span: tracing::Span },
}

#[derive(Debug, Clone)]
pub struct StorvscManagerClient {
    sender: mesh::Sender<Request>,
}

impl StorvscManagerClient {
    pub async fn get_or_create_disk(
        &self,
        instance_guid: guid::Guid,
        lun: u8,
    ) -> anyhow::Result<Arc<disk_storvsc::StorvscDisk>> {
        self.sender
            .call(Request::GetOrCreateDisk, (instance_guid, lun))
            .await
            .context("storvsc manager is shutdown")?
    }

    pub async fn save(&self) -> Option<StorvscManagerSavedState> {
        match self.sender.call(Request::Save, ()).await {
            Ok(s) => s.ok(),
            Err(_) => None,
        }
    }
}

#[derive(Inspect)]
struct StorvscManagerWorker {
    #[inspect(skip)]
    driver_source: VmTaskDriverSource,
    #[inspect(iter_by_key)]
    drivers: HashMap<guid::Guid, Arc<StorvscDriver<MappedRingMem>>>,
    /// Cached StorvscDisk instances, keyed by (controller_guid, lun).
    /// Both StorvscDiskConfig and StorvscDiskBounceConfig resolvers share
    /// the same underlying disk via this cache.
    #[inspect(skip)]
    disks: HashMap<(guid::Guid, u8), Arc<disk_storvsc::StorvscDisk>>,
    /// Saved metadata from pre-servicing save. Populated during restore,
    /// consumed lazily when disks are first resolved after servicing.
    #[inspect(skip)]
    saved_disk_metadata: HashMap<(guid::Guid, u8), disk_storvsc::StorvscDiskMetadata>,
    /// Running environment (memory layout) allows save/restore.
    save_restore_supported: bool,
    /// If this VM is isolated or not. This influences DMA client allocations.
    is_isolated: bool,
    #[inspect(skip)]
    dma_client_spawner: DmaClientSpawner,
}

impl StorvscManagerWorker {
    async fn run(&mut self, mut recv: mesh::Receiver<Request>) {
        let join_span = loop {
            let Some(req) = recv.next().await else {
                break tracing::Span::none();
            };
            match req {
                Request::Inspect(deferred) => deferred.inspect(&self),
                Request::GetOrCreateDisk(rpc) => {
                    rpc.handle(async |(guid, lun)| self.get_or_create_disk(guid, lun).await)
                        .await
                }
                Request::Save(rpc) => {
                    rpc.handle(async |_| self.save().await)
                        .instrument(tracing::info_span!("storvsc_save_state"))
                        .await
                }
                Request::Shutdown { span } => {
                    break span;
                }
            }
        };

        // Deep defensive: always stop drivers unconditionally on shutdown. stop()
        // is idempotent, so this is harmless when save() has already cleaned up.
        // Ensures no driver tasks or transactions are leaked regardless of how
        // the shutdown was triggered (normal shutdown, servicing, or unexpected
        // teardown).
        async {
            join_all(self.drivers.drain().map(|(guid, driver)| {
                let guid_str = guid.to_string();
                async move {
                    driver
                        .stop()
                        .instrument(tracing::info_span!(
                            "shutdown_storvsc_driver",
                            guid = guid_str
                        ))
                        .await
                }
            }))
            .await
        }
        .instrument(join_span)
        .await;
    }

    async fn get_driver(
        &mut self,
        instance_guid: guid::Guid,
    ) -> Result<Arc<StorvscDriver<MappedRingMem>>, InnerError> {
        let storvsc = match self.drivers.entry(instance_guid) {
            hash_map::Entry::Occupied(entry) => entry.get().clone(),
            hash_map::Entry::Vacant(entry) => {
                // Claim this SCSI controller for UIO from hv_storvsc.
                // hv_storvsc binds all SCSI channels at boot. We need to
                // steal specific relay controllers for usermode operation.
                claim_vmbus_device_for_uio(&instance_guid).await;

                let file = vmbus_user_channel::open_uio_device(&instance_guid)
                    .map_err(InnerError::Vmbus)?;

                let channel = vmbus_user_channel::channel(
                    &self.driver_source.simple(),
                    file,
                    Some(STORVSC_IN_RING_SIZE),
                    Some(STORVSC_OUT_RING_SIZE),
                )
                .map_err(InnerError::Vmbus)?;

                let dma_client = self
                    .dma_client_spawner
                    .new_client(DmaClientParameters {
                        device_name: format!("storvsc_{}", instance_guid),
                        lower_vtl_policy: LowerVtlPermissionPolicy::Any,
                        allocation_visibility: if self.is_isolated {
                            AllocationVisibility::Shared
                        } else {
                            AllocationVisibility::Private
                        },
                        persistent_allocations: self.save_restore_supported,
                    })
                    .map_err(InnerError::DmaClient)?;

                let mut driver = Arc::new(StorvscDriver::new(dma_client));

                Arc::get_mut(&mut driver)
                    .unwrap()
                    .run(
                        &self.driver_source,
                        channel,
                        storvsp_protocol::ProtocolVersion {
                            major_minor: storvsp_protocol::VERSION_BLUE,
                            reserved: 0,
                        },
                        0, // TODO: Pick right VP
                    )
                    .map_err(InnerError::DriverInitFailed)
                    .await?;

                entry.insert(driver).clone()
            }
        };
        Ok(storvsc)
    }

    /// Gets or creates a StorvscDisk for the given controller + LUN.
    /// On the restore path, uses saved metadata to avoid SCSI queries.
    async fn get_or_create_disk(
        &mut self,
        instance_guid: guid::Guid,
        lun: u8,
    ) -> anyhow::Result<Arc<disk_storvsc::StorvscDisk>> {
        let key = (instance_guid, lun);
        if let Some(disk) = self.disks.get(&key) {
            return Ok(disk.clone());
        }

        let driver = self
            .get_driver(instance_guid)
            .await
            .map_err(anyhow::Error::new)?;

        let disk = if let Some(meta) = self.saved_disk_metadata.remove(&key) {
            tracing::info!(
                %instance_guid,
                lun,
                sector_size = meta.sector_size,
                sector_count = meta.sector_count,
                "restoring StorvscDisk from saved metadata (skip SCSI queries)"
            );
            disk_storvsc::StorvscDisk::new_with_metadata(driver, lun, self.is_isolated, meta)
                .await
                .context("failed to restore StorvscDisk from metadata")?
        } else {
            disk_storvsc::StorvscDisk::new(driver, lun, self.is_isolated)
                .await
                .context("failed to create StorvscDisk")?
        };

        let disk = Arc::new(disk);
        self.disks.insert(key, disk.clone());
        Ok(disk)
    }

    /// Saves storvsc driver states and live disk metadata during servicing.
    /// Disk metadata is read from live AtomicU64 fields -- always fresh,
    /// no stale data risk even after runtime resizes.
    pub async fn save(&mut self) -> anyhow::Result<StorvscManagerSavedState> {
        let mut storvsc_drivers: Vec<StorvscSavedDriverConfig> = Vec::new();
        for (guid, driver) in self.drivers.iter_mut() {
            let mut disk_metadata = Vec::new();
            for (&(g, lun), disk) in &self.disks {
                if g == *guid {
                    let meta = disk.metadata();
                    disk_metadata.push(StorvscSavedDiskMetadata {
                        lun: lun as u32,
                        sector_count: meta.sector_count,
                        sector_size: meta.sector_size,
                        disk_id: meta.disk_id.map(|d| d.to_vec()).unwrap_or_default(),
                        read_only: meta.read_only,
                        optimal_unmap_sectors: meta.optimal_unmap_sectors,
                        device_type: meta.device_type as u32,
                    });
                }
            }
            storvsc_drivers.push(StorvscSavedDriverConfig {
                instance_guid: *guid,
                disk_metadata,
                driver_state: driver
                    .save()
                    .instrument(tracing::info_span!(
                        "storvsc_driver_save",
                        instance_guid = guid.to_string()
                    ))
                    .await?,
            });
        }

        Ok(StorvscManagerSavedState { storvsc_drivers })
    }

    /// Restores storvsc manager and driver states from the buffer after
    /// servicing. Disk metadata is saved for lazy consumption when disks
    /// are resolved via get_or_create_disk().
    pub async fn restore(&mut self, saved_state: &StorvscManagerSavedState) -> anyhow::Result<()> {
        self.drivers = HashMap::new();
        for driver_state in &saved_state.storvsc_drivers {
            // Claim this SCSI controller for UIO (restore path).
            claim_vmbus_device_for_uio(&driver_state.instance_guid).await;

            let file = vmbus_user_channel::open_uio_device(&driver_state.instance_guid)
                .map_err(InnerError::Vmbus)?;
            let channel = vmbus_user_channel::channel(
                &self.driver_source.simple(),
                file,
                Some(STORVSC_IN_RING_SIZE),
                Some(STORVSC_OUT_RING_SIZE),
            )
            .map_err(InnerError::Vmbus)?;

            let dma_client = self
                .dma_client_spawner
                .new_client(DmaClientParameters {
                    device_name: format!("storvsc_{}", driver_state.instance_guid),
                    lower_vtl_policy: LowerVtlPermissionPolicy::Any,
                    allocation_visibility: if self.is_isolated {
                        AllocationVisibility::Shared
                    } else {
                        AllocationVisibility::Private
                    },
                    persistent_allocations: self.save_restore_supported,
                })
                .map_err(InnerError::DmaClient)?;

            self.drivers.insert(
                driver_state.instance_guid,
                Arc::new(
                    StorvscDriver::restore(
                        &driver_state.driver_state,
                        &self.driver_source,
                        channel,
                        0,
                        dma_client,
                    )
                    .await?,
                ), // TODO: Pick right VP
            );

            // Populate saved disk metadata for lazy restore via get_or_create_disk().
            for disk_meta in &driver_state.disk_metadata {
                self.saved_disk_metadata.insert(
                    (driver_state.instance_guid, disk_meta.lun as u8),
                    disk_storvsc::StorvscDiskMetadata {
                        sector_count: disk_meta.sector_count,
                        sector_size: disk_meta.sector_size,
                        disk_id: if disk_meta.disk_id.len() == 16 {
                            Some(disk_meta.disk_id.as_slice().try_into().unwrap())
                        } else {
                            None
                        },
                        read_only: disk_meta.read_only,
                        optimal_unmap_sectors: disk_meta.optimal_unmap_sectors,
                        device_type: disk_meta.device_type as u8,
                    },
                );
            }
        }
        Ok(())
    }
}

/// Stateless resolver that asks the manager for disk instances.
/// The manager owns both the driver and disk caches, handling
/// save/restore internally.
#[derive(Clone)]
pub struct StorvscDiskResolver {
    manager: StorvscManagerClient,
}

impl StorvscDiskResolver {
    pub fn new(manager: StorvscManagerClient) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl AsyncResolveResource<DiskHandleKind, StorvscDiskConfig> for StorvscDiskResolver {
    type Output = ResolvedDisk;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        _resolver: &ResourceResolver,
        rsrc: StorvscDiskConfig,
        _input: ResolveDiskParameters<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let disk = self
            .manager
            .get_or_create_disk(rsrc.instance_guid, rsrc.lun)
            .await
            .context("could not open storvsc disk")?;

        ResolvedDisk::new(disk_storvsc::StorvscDiskBounce::new(disk, false)).context("invalid disk")
    }
}

#[derive(MeshPayload, Default)]
pub struct StorvscDiskConfig {
    pub instance_guid: guid::Guid,
    pub lun: u8,
}

impl ResourceId<DiskHandleKind> for StorvscDiskConfig {
    const ID: &'static str = "storvsc";
}

/// Config for resolving a StorvscDisk that always uses bounce buffers.
/// Used for IDE direct (port I/O) path where RequestBuffers contain fake
/// GPNs from the IDE CommandBuffer heap allocation.
#[derive(MeshPayload, Default)]
pub struct StorvscDiskBounceConfig {
    pub instance_guid: guid::Guid,
    pub lun: u8,
}

impl ResourceId<DiskHandleKind> for StorvscDiskBounceConfig {
    const ID: &'static str = "storvsc_bounce";
}

#[async_trait]
impl AsyncResolveResource<DiskHandleKind, StorvscDiskBounceConfig> for StorvscDiskResolver {
    type Output = ResolvedDisk;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        _resolver: &ResourceResolver,
        rsrc: StorvscDiskBounceConfig,
        _input: ResolveDiskParameters<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let disk = self
            .manager
            .get_or_create_disk(rsrc.instance_guid, rsrc.lun)
            .await
            .context("could not open storvsc disk for bounce")?;

        ResolvedDisk::new(disk_storvsc::StorvscDiskBounce::new(disk, true))
            .context("invalid bounce disk")
    }
}

pub mod save_restore {
    use mesh::payload::Protobuf;
    use vmcore::save_restore::SavedStateRoot;

    #[derive(Protobuf, SavedStateRoot)]
    #[mesh(package = "underhill")]
    pub struct StorvscManagerSavedState {
        #[mesh(1)]
        pub storvsc_drivers: Vec<StorvscSavedDriverConfig>,
    }

    #[derive(Protobuf, Clone)]
    #[mesh(package = "underhill")]
    pub struct StorvscSavedDriverConfig {
        #[mesh(1)]
        pub instance_guid: guid::Guid,
        #[mesh(2)]
        pub driver_state: storvsc_driver::save_restore::StorvscDriverSavedState,
        #[mesh(3)]
        pub disk_metadata: Vec<StorvscSavedDiskMetadata>,
    }

    /// Per-LUN disk metadata saved across servicing to avoid re-querying
    /// capacity via SCSI commands on restore.
    #[derive(Protobuf, Clone)]
    #[mesh(package = "underhill")]
    pub struct StorvscSavedDiskMetadata {
        #[mesh(1)]
        pub lun: u32,
        #[mesh(2)]
        pub sector_count: u64,
        #[mesh(3)]
        pub sector_size: u32,
        #[mesh(4)]
        pub disk_id: Vec<u8>,
        #[mesh(5)]
        pub read_only: bool,
        #[mesh(6)]
        pub optimal_unmap_sectors: u32,
        #[mesh(7)]
        pub device_type: u32,
    }
}

/// SCSI VMBus interface class GUID.
const SCSI_CLASS_GUID: &str = "ba6163d9-04a1-4d29-b605-72e2ffb1dc7f";

/// Claim a VMBus SCSI channel for UIO from hv_storvsc.
///
/// At boot, hv_storvsc.ko claims all SCSI VMBus channels. When storvsc_manager
/// needs a specific controller for usermode relay, this function:
/// 1. Registers UIO for SCSI class (idempotent, allows UIO to match SCSI)
/// 2. Unbinds the specific controller from hv_storvsc
/// 3. Binds it to uio_hv_generic
///
/// VTL2-internal SCSI channels (cidata, diagnostics) stay on hv_storvsc.
///
/// # Error Handling
///
/// Currently fire-and-forget: errors at each step are logged but do not
/// prevent the caller from attempting `open_uio_device`, which will fail
/// if the device was not successfully bound to UIO. This results in a
/// hard failure for that SCSI controller.
///
/// TODO: Consider returning `Result` and falling back to kernel hv_storvsc
/// when UIO claiming fails. This would allow the disk to remain accessible
/// via the kernel driver path (slower but functional). The fallback would
/// need to be wired into `StorvscDiskResolver::resolve()` to re-route the
/// device through `get_vscsi_devname()` instead.
async fn claim_vmbus_device_for_uio(instance_guid: &guid::Guid) {
    let device_id = instance_guid.to_string();
    let guid_for_log = *instance_guid;

    // All sysfs writes are blocking I/O -- run them off the async executor.
    blocking::unblock(move || {
        // Step 1: Ensure UIO knows about SCSI class (idempotent).
        // This is needed so uio_hv_generic will accept the bind.
        if let Err(e) = std::fs::write(
            "/sys/bus/vmbus/drivers/uio_hv_generic/new_id",
            SCSI_CLASS_GUID,
        ) {
            // EEXIST is fine -- means it's already registered.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                tracing::warn!(
                    instance_guid = %guid_for_log,
                    error = %e,
                    "failed to register SCSI class for UIO (may already be registered)"
                );
            }
        }

        // Step 2: Unbind from hv_storvsc (if currently bound there).
        match std::fs::write("/sys/bus/vmbus/drivers/hv_storvsc/unbind", &device_id) {
            Ok(()) => {
                tracing::info!(
                    instance_guid = %guid_for_log,
                    "unbound SCSI channel from hv_storvsc for usermode relay"
                );
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::ENODEV) {
                    // ENODEV: device not bound to hv_storvsc -- expected
                    // when already on UIO or unbound.
                    tracing::debug!(
                        instance_guid = %guid_for_log,
                        "hv_storvsc unbind skipped (device not bound there)"
                    );
                } else {
                    // Unexpected error (EPERM, EACCES, etc.)
                    tracing::warn!(
                        instance_guid = %guid_for_log,
                        error = %e,
                        "hv_storvsc unbind failed unexpectedly"
                    );
                }
            }
        }

        // Step 3: Bind to uio_hv_generic.
        match std::fs::write("/sys/bus/vmbus/drivers/uio_hv_generic/bind", &device_id) {
            Ok(()) => {
                tracing::info!(
                    instance_guid = %guid_for_log,
                    "bound SCSI channel to UIO for usermode relay"
                );
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    // EBUSY: already bound to UIO -- expected.
                    tracing::debug!(
                        instance_guid = %guid_for_log,
                        "UIO bind skipped (device already bound)"
                    );
                } else {
                    // Unexpected error -- may cause open_uio_device to fail.
                    tracing::warn!(
                        instance_guid = %guid_for_log,
                        error = %e,
                        "UIO bind failed unexpectedly"
                    );
                }
            }
        }
    })
    .await;
}
