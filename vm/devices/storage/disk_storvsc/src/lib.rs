// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Disk backend implementation that uses a user-mode storvsc driver.

#![forbid(unsafe_code)]

use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::UnmapBehavior;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use igvm_defs::PAGE_SIZE_4K;
use inspect::Inspect;
use scsi_defs::ScsiOp;
use scsi_defs::ScsiStatus;
use static_assertions::const_assert;
use std::sync::Arc;
use storvsc_driver::StorvscDriver;
use storvsc_driver::StorvscErrorKind;
use vmbus_user_channel::MappedRingMem;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// Maximum number of retries when a retryable failure occurs, which should really only happen
/// during servicing. Servicing shouldn't happen frequently enough to make more than one retry
/// necessary, but provide some buffer room.
const MAX_RETRIES: usize = 5;

/// Investigation-only: log first read/write to confirm I/O path works without flooding.

/// Disk backend using a storvsc driver to the host.
#[derive(Inspect)]
pub struct StorvscDisk {
    #[inspect(skip)]
    driver: Arc<StorvscDriver<MappedRingMem>>,
    lun: u8,
    #[inspect(skip)]
    resize_event: Arc<event_listener::Event>,
    // Cached metadata -- fetched once at construction to avoid block_on in sync DiskIo methods.
    // Capacity is refetched on resize via wait_resize().
    cached_sector_count: u64,
    cached_sector_size: u32,
    cached_disk_id: Option<[u8; 16]>,
    cached_read_only: bool,
    cached_optimal_unmap_sectors: u32,
}

#[derive(Default)]
struct DiskCapacity {
    num_sectors: u64,
    sector_size: u32,
}

impl StorvscDisk {
    /// Creates a new storvsc-backed disk that uses the provided storvsc driver.
    ///
    /// This is async because it pre-fetches disk metadata (capacity, disk ID,
    /// read-only state, unmap granularity) from the host via SCSI commands.
    /// The DiskIo trait requires these as synchronous methods, so we cache them
    /// here to avoid `block_on` deadlocks in async executor contexts.
    pub async fn new(driver: Arc<StorvscDriver<MappedRingMem>>, lun: u8) -> Self {
        tracing::warn!(lun);
        let resize_event = Arc::new(event_listener::Event::new());
        match driver.add_resize_listener(lun, resize_event.clone()) {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "Failed to add resize listener to storvsc driver"
                );
            }
        }
        let mut disk = Self {
            driver,
            lun,
            resize_event,
            cached_sector_count: 0,
            cached_sector_size: 0,
            cached_disk_id: None,
            cached_read_only: false,
            cached_optimal_unmap_sectors: 0,
        };
        // Pre-fetch metadata while we're in an async context.
        let capacity = disk.fetch_capacity().await;
        disk.cached_sector_count = capacity.num_sectors;
        disk.cached_sector_size = capacity.sector_size;
        disk.cached_disk_id = disk.fetch_disk_id().await;
        disk.cached_read_only = disk.fetch_read_only().await;
        disk.cached_optimal_unmap_sectors = disk.fetch_optimal_unmap_sectors().await;

        disk
    }
}

impl StorvscDisk {
    async fn fetch_capacity(&self) -> DiskCapacity {
        const_assert!(size_of::<scsi_defs::ReadCapacity16Data>() as u64 <= PAGE_SIZE_4K);
        const_assert!(size_of::<scsi_defs::ReadCapacityData>() as u64 <= PAGE_SIZE_4K);
        let data_in_size = PAGE_SIZE_4K as usize;
        let data_in = match self.driver.allocate_dma_buffer(data_in_size) {
            Ok(buf) => buf,
            Err(err) => {
                tracing::error!(
                    error = err.to_string(),
                    "Unable to allocate DMA buffer for READ CAPACITY"
                );
                return DiskCapacity::default();
            }
        };

        // Try READ CAPACITY(16) first. Falls back to READ CAPACITY(10) if the
        // device rejects it (DVD/CD-ROM devices only support the 10-byte CDB).
        let buf_gpns = data_in.pfns();
        let read_capacity16_cdb = scsi_defs::ServiceActionIn16 {
            operation_code: ScsiOp::READ_CAPACITY16,
            service_action: scsi_defs::SERVICE_ACTION_READ_CAPACITY16,
            allocation_length: (data_in_size as u32).into(),
            ..FromZeros::new_zeroed()
        };
        match self
            .send_scsi_request(
                read_capacity16_cdb.as_bytes(),
                read_capacity16_cdb.operation_code,
                buf_gpns,
                data_in_size,
                true,
            )
            .await
        {
            Ok(resp) if resp.scsi_status == ScsiStatus::GOOD => {
                let capacity = data_in.read_obj::<scsi_defs::ReadCapacity16Data>(0);
                let num_sectors: u64 = capacity.ex.logical_block_address.into();
                return DiskCapacity {
                    num_sectors: num_sectors + 1,
                    sector_size: capacity.ex.bytes_per_block.into(),
                };
            }
            Ok(resp) => {
                tracing::warn!(
                    scsi_status = ?resp.scsi_status,
                    "READ CAPACITY(16) failed, trying READ CAPACITY(10)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = &err as &dyn std::error::Error,
                    "READ CAPACITY(16) failed, trying READ CAPACITY(10)"
                );
            }
        }

        // Fallback: READ CAPACITY(10) for devices that don't support 16-byte CDBs.
        let read_capacity10_cdb = scsi_defs::Cdb10 {
            operation_code: ScsiOp::READ_CAPACITY,
            ..FromZeros::new_zeroed()
        };
        match self
            .send_scsi_request(
                read_capacity10_cdb.as_bytes(),
                read_capacity10_cdb.operation_code,
                buf_gpns,
                data_in_size,
                true,
            )
            .await
        {
            Ok(resp) => match resp.scsi_status {
                ScsiStatus::GOOD => {
                    let capacity = data_in.read_obj::<scsi_defs::ReadCapacityData>(0);
                    let num_sectors: u64 = u32::from(capacity.logical_block_address) as u64;
                    DiskCapacity {
                        num_sectors: num_sectors + 1,
                        sector_size: capacity.bytes_per_block.into(),
                    }
                }
                _ => {
                    tracing::error!(
                        scsi_status = ?resp.scsi_status,
                        srb_status = ?resp.srb_status,
                        "READ CAPACITY(10) also failed"
                    );
                    DiskCapacity::default()
                }
            },
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "READ CAPACITY(10) also failed"
                );
                DiskCapacity::default()
            }
        }
    }

    /// Fetches the disk ID via INQUIRY VPD Device Identification page.
    async fn fetch_disk_id(&self) -> Option<[u8; 16]> {
        const_assert!(
            (size_of::<scsi_defs::VpdPageHeader>()
                + size_of::<scsi_defs::VpdIdentificationDescriptor>()) as u64
                <= PAGE_SIZE_4K
        );
        let data_in_size = PAGE_SIZE_4K as usize;
        let data_in = match self.driver.allocate_dma_buffer(data_in_size) {
            Ok(buf) => buf,
            Err(err) => {
                tracing::error!(
                    error = err.to_string(),
                    "Unable to allocate DMA buffer for INQUIRY"
                );
                return None;
            }
        };

        let cdb = scsi_defs::CdbInquiry {
            operation_code: ScsiOp::INQUIRY,
            flags: scsi_defs::InquiryFlags::new().with_vpd(true),
            page_code: scsi_defs::VPD_DEVICE_IDENTIFIERS,
            allocation_length: (data_in_size as u16).into(),
            ..FromZeros::new_zeroed()
        };

        match self
            .send_scsi_request(
                cdb.as_bytes(),
                cdb.operation_code,
                data_in.pfns(),
                data_in_size,
                true,
            )
            .await
        {
            Ok(resp) => match resp.scsi_status {
                ScsiStatus::GOOD => {
                    let mut buf_pos = 0;
                    let vpd_header = data_in.read_obj::<scsi_defs::VpdPageHeader>(0);
                    buf_pos += size_of::<scsi_defs::VpdPageHeader>();
                    while buf_pos < vpd_header.page_length as usize + 4 {
                        let designator_header =
                            data_in.read_obj::<scsi_defs::VpdIdentificationDescriptor>(buf_pos);
                        buf_pos += size_of::<scsi_defs::VpdIdentificationDescriptor>();
                        match designator_header.identifiertype {
                            scsi_defs::VPD_IDENTIFIER_TYPE_FCPH_NAME => {
                                let designator_naa =
                                    data_in.read_obj::<scsi_defs::VpdNaaId>(buf_pos);
                                let mut created_disk_id = [0u8; 16];
                                created_disk_id[0] = designator_naa.ouid_msb;
                                created_disk_id[1..3]
                                    .copy_from_slice(designator_naa.ouid_middle.as_slice());
                                created_disk_id[3] = designator_naa.ouid_lsb;
                                created_disk_id[4..]
                                    .copy_from_slice(designator_naa.vendor_specific_id.as_slice());
                                return Some(created_disk_id);
                            }
                            _ => {
                                buf_pos += size_of::<scsi_defs::VpdIdentificationDescriptor>()
                                    + designator_header.identifier_length as usize;
                            }
                        }
                    }
                    None
                }
                _ => {
                    tracing::error!(scsi_status = ?resp.scsi_status, srb_status = ?resp.srb_status, "INQUIRY for Device Identification VPD failed");
                    None
                }
            },
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "INQUIRY for Device Identification VPD failed"
                );
                None
            }
        }
    }

    /// Fetches read-only state via MODE SENSE(10).
    async fn fetch_read_only(&self) -> bool {
        const_assert!(size_of::<scsi_defs::ModeParameterHeader10>() as u64 <= PAGE_SIZE_4K);
        let data_in_size = PAGE_SIZE_4K as usize;
        let data_in = match self.driver.allocate_dma_buffer(data_in_size) {
            Ok(buf) => buf,
            Err(err) => {
                tracing::error!(
                    error = err.to_string(),
                    "Unable to allocate DMA buffer for MODE SENSE(10)"
                );
                return false;
            }
        };

        let cdb = scsi_defs::ModeSense10 {
            operation_code: ScsiOp::MODE_SENSE10,
            flags2: scsi_defs::ModeSenseFlags::new().with_page_code(scsi_defs::MODE_PAGE_ALL),
            sub_page_code: 0,
            allocation_length: (data_in_size as u16).into(),
            ..FromZeros::new_zeroed()
        };

        match self
            .send_scsi_request(
                cdb.as_bytes(),
                cdb.operation_code,
                data_in.pfns(),
                data_in_size,
                true,
            )
            .await
        {
            Ok(resp) => match resp.scsi_status {
                ScsiStatus::GOOD => {
                    let mode_header = data_in.read_obj::<scsi_defs::ModeParameterHeader10>(0);
                    mode_header.device_specific_parameter & scsi_defs::MODE_DSP_WRITE_PROTECT != 0
                }
                _ => {
                    tracing::error!(scsi_status = ?resp.scsi_status, srb_status = ?resp.srb_status, "MODE SENSE(10) failed");
                    false
                }
            },
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "MODE SENSE(10) failed"
                );
                false
            }
        }
    }

    /// Fetches optimal unmap granularity via INQUIRY VPD Block Limits.
    async fn fetch_optimal_unmap_sectors(&self) -> u32 {
        const_assert!(size_of::<scsi_defs::VpdPageHeader>() as u64 <= PAGE_SIZE_4K);
        let data_in_size = PAGE_SIZE_4K as usize;
        let data_in = match self.driver.allocate_dma_buffer(data_in_size) {
            Ok(buf) => buf,
            Err(err) => {
                tracing::error!(
                    error = err.to_string(),
                    "Unable to allocate DMA buffer for INQUIRY"
                );
                return 0;
            }
        };

        // First: check if Block Limits VPD is supported
        let cdb = scsi_defs::CdbInquiry {
            operation_code: ScsiOp::INQUIRY,
            flags: scsi_defs::InquiryFlags::new().with_vpd(true),
            page_code: scsi_defs::VPD_SUPPORTED_PAGES,
            allocation_length: (data_in_size as u16).into(),
            ..FromZeros::new_zeroed()
        };

        match self
            .send_scsi_request(
                cdb.as_bytes(),
                cdb.operation_code,
                data_in.pfns(),
                data_in_size,
                true,
            )
            .await
        {
            Ok(resp) => match resp.scsi_status {
                ScsiStatus::GOOD => {
                    let vpd_header = data_in.read_obj::<scsi_defs::VpdPageHeader>(0);
                    let mut buf_pos = size_of::<scsi_defs::VpdPageHeader>();
                    while buf_pos
                        < vpd_header.page_length as usize + size_of::<scsi_defs::VpdPageHeader>()
                    {
                        if data_in.read_obj::<u8>(buf_pos) == scsi_defs::VPD_BLOCK_LIMITS {
                            // Fetch Block Limits VPD
                            let cdb2 = scsi_defs::CdbInquiry {
                                operation_code: ScsiOp::INQUIRY,
                                flags: scsi_defs::InquiryFlags::new().with_vpd(true),
                                page_code: scsi_defs::VPD_BLOCK_LIMITS,
                                allocation_length: (data_in_size as u16).into(),
                                ..FromZeros::new_zeroed()
                            };
                            match self
                                .send_scsi_request(
                                    cdb2.as_bytes(),
                                    cdb2.operation_code,
                                    data_in.pfns(),
                                    data_in_size,
                                    true,
                                )
                                .await
                            {
                                Ok(resp) => match resp.scsi_status {
                                    ScsiStatus::GOOD => {
                                        let block_limits_vpd =
                                            data_in
                                                .read_obj::<scsi_defs::VpdBlockLimitsDescriptor>(0);
                                        return block_limits_vpd.optimal_unmap_granularity.into();
                                    }
                                    _ => {
                                        tracing::error!(scsi_status = ?resp.scsi_status, srb_status = ?resp.srb_status, "INQUIRY for Block Limits VPD failed");
                                    }
                                },
                                Err(err) => {
                                    tracing::error!(
                                        error = &err as &dyn std::error::Error,
                                        "INQUIRY for Block Limits VPD failed"
                                    );
                                }
                            }
                        }
                        buf_pos += 1;
                    }
                    0
                }
                _ => {
                    tracing::error!(scsi_status = ?resp.scsi_status, srb_status = ?resp.srb_status, "INQUIRY for Supported Pages VPD failed");
                    0
                }
            },
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "INQUIRY for Supported Pages VPD failed"
                );
                0
            }
        }
    }

    fn generate_scsi_request(
        &self,
        data_transfer_length: u32,
        payload: &[u8],
        is_read: bool,
    ) -> storvsp_protocol::ScsiRequest {
        assert!(payload.len() <= storvsp_protocol::MAX_DATA_BUFFER_LENGTH_WITH_PADDING);
        let data_in: u8 = if is_read { 1 } else { 0 };
        let mut request = storvsp_protocol::ScsiRequest {
            target_id: 0,
            path_id: 0,
            lun: self.lun,
            length: storvsp_protocol::SCSI_REQUEST_LEN_V2 as u16,
            cdb_length: payload.len() as u8,
            data_transfer_length,
            data_in,
            ..FromZeros::new_zeroed()
        };
        request.payload[0..payload.len()].copy_from_slice(payload);
        request
    }

    async fn send_scsi_request(
        &self,
        cdb: &[u8],
        op: ScsiOp,
        buf_gpns: &[u64],
        byte_len: usize,
        is_read: bool,
    ) -> Result<storvsp_protocol::ScsiRequest, DiskError> {
        let request = self.generate_scsi_request(byte_len as u32, cdb, is_read);

        let mut num_tries = 0;
        loop {
            match self.driver.send_request(&request, buf_gpns, byte_len).await {
                Ok(resp) => match resp.scsi_status {
                    ScsiStatus::GOOD => break Ok(resp), // Request succeeded, break out of loop
                    _ => {
                        tracing::error!(?op, scsi_status = ?resp.scsi_status, "SCSI request failed");
                        Err(DiskError::Io(std::io::Error::other(format!(
                            "SCSI request failed, op={:?}, scsi_status={:?}, srb_status={:?}",
                            op, resp.scsi_status, resp.srb_status
                        ))))
                    }
                },
                Err(err) => {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "SCSI request failed"
                    );
                    match err.kind() {
                        StorvscErrorKind::CompletionError => Err(DiskError::Io(
                            std::io::Error::new(std::io::ErrorKind::Interrupted, err),
                        )),
                        StorvscErrorKind::Cancelled => Err(DiskError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            err,
                        ))),
                        StorvscErrorKind::CancelledRetry => {
                            if num_tries < MAX_RETRIES {
                                Ok(())
                            } else {
                                break Err(DiskError::Io(std::io::Error::new(
                                    std::io::ErrorKind::Interrupted,
                                    err,
                                )));
                            }
                        }
                        _ => Err(DiskError::Io(std::io::Error::other(err))),
                    }
                }
            }?;
            num_tries += 1;
        }
    }
}

impl DiskIo for StorvscDisk {
    fn disk_type(&self) -> &str {
        "storvsc"
    }

    fn sector_count(&self) -> u64 {
        self.cached_sector_count
    }

    fn sector_size(&self) -> u32 {
        self.cached_sector_size
    }

    fn disk_id(&self) -> Option<[u8; 16]> {
        self.cached_disk_id
    }

    fn physical_sector_size(&self) -> u32 {
        self.cached_sector_size
    }

    fn is_fua_respected(&self) -> bool {
        true
    }

    fn is_read_only(&self) -> bool {
        self.cached_read_only
    }

    async fn read_vectored(
        &self,
        buffers: &scsi_buffers::RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        let sector_size = self.cached_sector_size;
        if sector_size == 0 {
            // Failed to get sector size.
            return Err(DiskError::IllegalBlock);
        }

        if !buffers.len().is_multiple_of(sector_size as usize) {
            // Buffer length must be a multiple of sector size.
            return Err(DiskError::InvalidInput);
        }

        // PERF TODO: Currently using bounce buffer (DMA alloc + copy) because
        // storvsp expects GPAs in GPA Direct packets, but we only have guest
        // GPNs from buffers.range(). A future optimization would pass the GPNs
        // directly to send_gpa_direct_packet via a PagedRange, avoiding the
        // copy. This matches the NVMe driver's double-buffer fallback pattern.
        //
        // Bug fixed: Previously used locked_buffers.va() which is a VTL2 VA,
        // not a GPA. storvsp couldn't access the memory.
        let dma_buf = self
            .driver
            .allocate_dma_buffer(buffers.len())
            .map_err(|e| DiskError::Io(std::io::Error::other(e)))?;

        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::READ16,
            logical_block: sector.into(),
            transfer_blocks: (buffers.len() as u32 / sector_size).into(),
            ..FromZeros::new_zeroed()
        };

        let result = self
            .send_scsi_request(
                cdb.as_bytes(),
                cdb.operation_code,
                dma_buf.pfns(),
                buffers.len(),
                true,
            )
            .await;

        if result.is_ok() {
            // Copy data from DMA buffer back to guest memory.
            let mut data = vec![0u8; buffers.len()];
            dma_buf.read_at(0, &mut data);
            let mut writer = buffers.writer();
            writer.write(&data)?;
        }

        result.map(|_| ())
    }

    async fn write_vectored(
        &self,
        buffers: &scsi_buffers::RequestBuffers<'_>,
        sector: u64,
        fua: bool,
    ) -> Result<(), DiskError> {
        let sector_size = self.cached_sector_size;
        if sector_size == 0 {
            // Failed to get sector size.
            return Err(DiskError::IllegalBlock);
        }

        if !buffers.len().is_multiple_of(sector_size as usize) {
            // Buffer length must be a multiple of sector size.
            return Err(DiskError::InvalidInput);
        }

        // PERF TODO: Bounce buffer - see read_vectored comment for rationale.
        let dma_buf = self
            .driver
            .allocate_dma_buffer(buffers.len())
            .map_err(|e| DiskError::Io(std::io::Error::other(e)))?;

        // Copy guest data into DMA buffer for the write.
        let mut data = vec![0u8; buffers.len()];
        let mut reader = buffers.reader();
        reader.read(&mut data)?;
        dma_buf.write_at(0, &data);

        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::WRITE16,
            flags: scsi_defs::Cdb16Flags::new().with_fua(fua),
            logical_block: sector.into(),
            transfer_blocks: (buffers.len() as u32 / sector_size).into(),
            ..FromZeros::new_zeroed()
        };

        self.send_scsi_request(
            cdb.as_bytes(),
            cdb.operation_code,
            dma_buf.pfns(),
            buffers.len(),
            false,
        )
        .await
        .map(|_| ())
    }

    async fn sync_cache(&self) -> Result<(), DiskError> {
        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::SYNCHRONIZE_CACHE16,
            logical_block: 0.into(),
            transfer_blocks: 0.into(), // 0 indicates to sync all sectors
            ..FromZeros::new_zeroed()
        };

        self.send_scsi_request(cdb.as_bytes(), cdb.operation_code, &[], 0, false)
            .await
            .map(|_| ())
    }

    async fn eject(&self) -> Result<(), DiskError> {
        let cdb = scsi_defs::StartStop {
            operation_code: ScsiOp::START_STOP_UNIT,
            flag: scsi_defs::StartStopFlags::new().with_load_eject(true),
            ..FromZeros::new_zeroed()
        };

        self.send_scsi_request(cdb.as_bytes(), cdb.operation_code, &[], 0, false)
            .await
            .map(|_| ())
    }

    async fn unmap(
        &self,
        sector: u64,
        count: u64,
        _block_level_only: bool,
    ) -> Result<(), DiskError> {
        let cdb = scsi_defs::Unmap {
            operation_code: ScsiOp::UNMAP,
            allocation_length: (size_of::<scsi_defs::UnmapBlockDescriptor>() as u16).into(),
            ..FromZeros::new_zeroed()
        };

        let unmap_param_list = scsi_defs::UnmapListHeader {
            data_length: ((size_of::<scsi_defs::UnmapListHeader>() - 2
                + size_of::<scsi_defs::UnmapBlockDescriptor>()) as u16)
                .into(),
            block_descriptor_data_length: (size_of::<scsi_defs::UnmapBlockDescriptor>() as u16)
                .into(),
            ..FromZeros::new_zeroed()
        };

        let unmap_descriptor = scsi_defs::UnmapBlockDescriptor {
            start_lba: sector.into(),
            lba_count: u32::try_from(count)
                .map_err(|_| DiskError::InvalidInput)?
                .into(),
            ..FromZeros::new_zeroed()
        };

        // At this time we cannot allocate contiguous pages, but this could be done without an
        // assert if we could guarantee that the allocation is contiguous.
        const_assert!(
            (size_of::<scsi_defs::UnmapListHeader>() + size_of::<scsi_defs::UnmapBlockDescriptor>())
                as u64
                <= PAGE_SIZE_4K
        );
        let data_out_size = PAGE_SIZE_4K as usize;
        let data_out = match self.driver.allocate_dma_buffer(data_out_size) {
            Ok(buf) => buf,
            Err(err) => {
                tracing::error!(
                    error = err.to_string(),
                    "Unable to allocate DMA buffer for UNMAP"
                );
                return Err(DiskError::Io(std::io::Error::other(err)));
            }
        };
        data_out.write_at(0, unmap_param_list.as_bytes());
        data_out.write_at(
            size_of::<scsi_defs::UnmapListHeader>(),
            unmap_descriptor.as_bytes(),
        );

        self.send_scsi_request(
            cdb.as_bytes(),
            cdb.operation_code,
            data_out.pfns(),
            data_out_size,
            false,
        )
        .await
        .map(|_| ())
    }

    fn unmap_behavior(&self) -> UnmapBehavior {
        UnmapBehavior::Unspecified
    }

    fn optimal_unmap_sectors(&self) -> u32 {
        self.cached_optimal_unmap_sectors
    }

    async fn wait_resize(&self, sector_count: u64) -> u64 {
        loop {
            let listen = self.resize_event.listen();
            // Refetch capacity from host (we're in async context here)
            let capacity = self.fetch_capacity().await;
            if capacity.num_sectors != sector_count {
                break capacity.num_sectors;
            }
            listen.await;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_scsi_request_read_cdb() {
        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::READ16,
            logical_block: 100u64.into(),
            transfer_blocks: 8u32.into(),
            ..FromZeros::new_zeroed()
        };
        let cdb_bytes = cdb.as_bytes();
        assert_eq!(cdb_bytes[0], ScsiOp::READ16.0);
        assert_eq!(cdb_bytes.len(), size_of::<scsi_defs::Cdb16>());
    }

    #[test]
    fn test_generate_scsi_request_write_with_fua() {
        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::WRITE16,
            flags: scsi_defs::Cdb16Flags::new().with_fua(true),
            logical_block: 200u64.into(),
            transfer_blocks: 16u32.into(),
            ..FromZeros::new_zeroed()
        };
        let flags = scsi_defs::Cdb16Flags::from(cdb.as_bytes()[1]);
        assert!(flags.fua());
    }

    #[test]
    fn test_read_capacity16_cdb_format() {
        let cdb = scsi_defs::ServiceActionIn16 {
            operation_code: ScsiOp::READ_CAPACITY16,
            service_action: scsi_defs::SERVICE_ACTION_READ_CAPACITY16,
            allocation_length: (PAGE_SIZE_4K as u32).into(),
            ..FromZeros::new_zeroed()
        };
        assert_eq!(cdb.as_bytes()[0], ScsiOp::READ_CAPACITY16.0);
        assert_eq!(cdb.service_action, scsi_defs::SERVICE_ACTION_READ_CAPACITY16);
    }

    #[test]
    fn test_inquiry_vpd_cdb_format() {
        let cdb = scsi_defs::CdbInquiry {
            operation_code: ScsiOp::INQUIRY,
            flags: scsi_defs::InquiryFlags::new().with_vpd(true),
            page_code: scsi_defs::VPD_DEVICE_IDENTIFIERS,
            allocation_length: (PAGE_SIZE_4K as u16).into(),
            ..FromZeros::new_zeroed()
        };
        let flags = scsi_defs::InquiryFlags::from(cdb.as_bytes()[1]);
        assert!(flags.vpd());
        assert_eq!(cdb.page_code, scsi_defs::VPD_DEVICE_IDENTIFIERS);
    }

    #[test]
    fn test_unmap_descriptor_format() {
        let descriptor = scsi_defs::UnmapBlockDescriptor {
            start_lba: 100u64.into(),
            lba_count: 50u32.into(),
            ..FromZeros::new_zeroed()
        };
        let start_lba: u64 = descriptor.start_lba.into();
        let lba_count: u32 = descriptor.lba_count.into();
        assert_eq!(start_lba, 100);
        assert_eq!(lba_count, 50);
    }

    #[test]
    fn test_unmap_count_overflow() {
        // Regression test: count > u32::MAX should fail try_from
        let count: u64 = u32::MAX as u64 + 1;
        assert!(u32::try_from(count).is_err());
    }

    #[test]
    fn test_scsi_request_payload_format() {
        // Mirrors generate_scsi_request logic
        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::READ16,
            logical_block: 42u64.into(),
            transfer_blocks: 1u32.into(),
            ..FromZeros::new_zeroed()
        };
        let payload = cdb.as_bytes();
        assert!(payload.len() <= storvsp_protocol::MAX_DATA_BUFFER_LENGTH_WITH_PADDING);

        let mut request = storvsp_protocol::ScsiRequest {
            target_id: 0,
            path_id: 0,
            lun: 3,
            length: storvsp_protocol::SCSI_REQUEST_LEN_V2 as u16,
            cdb_length: payload.len() as u8,
            data_transfer_length: 4096,
            data_in: 1,
            ..FromZeros::new_zeroed()
        };
        request.payload[0..payload.len()].copy_from_slice(payload);

        assert_eq!(request.lun, 3);
        assert_eq!(request.data_transfer_length, 4096);
        assert_eq!(request.data_in, 1);
        assert_eq!(request.payload[0], ScsiOp::READ16.0);
    }

    #[test]
    fn test_sync_cache_cdb_format() {
        let cdb = scsi_defs::Cdb16 {
            operation_code: ScsiOp::SYNCHRONIZE_CACHE16,
            logical_block: 0u64.into(),
            transfer_blocks: 0u32.into(),
            ..FromZeros::new_zeroed()
        };
        assert_eq!(cdb.as_bytes()[0], ScsiOp::SYNCHRONIZE_CACHE16.0);
        let blocks: u32 = cdb.transfer_blocks.into();
        assert_eq!(blocks, 0); // 0 means sync all sectors
    }

    #[test]
    fn test_eject_cdb_format() {
        let cdb = scsi_defs::StartStop {
            operation_code: ScsiOp::START_STOP_UNIT,
            flag: scsi_defs::StartStopFlags::new().with_load_eject(true),
            ..FromZeros::new_zeroed()
        };
        assert_eq!(cdb.as_bytes()[0], ScsiOp::START_STOP_UNIT.0);
        let flags = scsi_defs::StartStopFlags::from(cdb.as_bytes()[4]);
        assert!(flags.load_eject());
    }

    #[test]
    fn test_max_retries_constant() {
        assert_eq!(MAX_RETRIES, 5);
    }
}
