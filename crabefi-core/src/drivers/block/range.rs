//! Bounded byte access to a range of device blocks.
//!
//! Partial blocks use read-modify-write; full blocks use the device's bulk
//! interface. A failed write may have changed part of the requested range.

use super::{BlockDevice, BlockError};

#[cfg(test)]
#[path = "range_tests.rs"]
mod tests;

const MAX_BLOCK_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct BlockRange {
    start: u64,
    blocks: u64,
}

/// Prefix completed by successful device calls. The failed call itself may
/// have changed additional bytes, which cannot be counted reliably.
#[derive(Debug)]
pub struct BlockWriteError {
    pub error: BlockError,
    pub completed: usize,
}

impl BlockRange {
    pub fn new(device: &dyn BlockDevice, start: u64, blocks: u64) -> Result<Self, BlockError> {
        let info = device.info();
        if blocks == 0
            || start
                .checked_add(blocks)
                .is_none_or(|end| end > info.num_blocks)
        {
            return Err(BlockError::OutOfRange);
        }
        if !(512..=MAX_BLOCK_SIZE as u32).contains(&info.block_size)
            || !info.block_size.is_power_of_two()
        {
            return Err(BlockError::InvalidParameter);
        }
        Ok(Self { start, blocks })
    }

    pub fn byte_len(&self, device: &dyn BlockDevice) -> Result<u64, BlockError> {
        self.blocks
            .checked_mul(device.info().block_size as u64)
            .ok_or(BlockError::OutOfRange)
    }

    fn check(
        &self,
        device: &dyn BlockDevice,
        offset: u64,
        len: usize,
    ) -> Result<usize, BlockError> {
        // Recheck live geometry: a borrowed range does not confer media identity.
        Self::new(device, self.start, self.blocks)?;
        let limit = self.byte_len(device)?;
        if offset.checked_add(len as u64).is_none_or(|end| end > limit) {
            return Err(BlockError::OutOfRange);
        }
        Ok(device.info().block_size as usize)
    }

    pub fn read(
        &self,
        device: &mut dyn BlockDevice,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), BlockError> {
        let block_size = self.check(device, offset, output.len())?;
        let mut scratch = [0; MAX_BLOCK_SIZE];
        let mut done = 0;
        while done < output.len() {
            let position = offset + done as u64;
            let lba = self.start + position / block_size as u64;
            let within = (position % block_size as u64) as usize;
            let remaining = output.len() - done;
            if within == 0 && remaining >= block_size {
                let count = (remaining / block_size).min(u32::MAX as usize) as u32;
                let len = count as usize * block_size;
                device.read_blocks(lba, count, &mut output[done..done + len])?;
                done += len;
            } else {
                device.read_block(lba, &mut scratch[..block_size])?;
                let len = (block_size - within).min(remaining);
                output[done..done + len].copy_from_slice(&scratch[within..within + len]);
                done += len;
            }
        }
        Ok(())
    }

    pub fn write(
        &self,
        device: &mut dyn BlockDevice,
        offset: u64,
        input: &[u8],
    ) -> Result<(), BlockError> {
        self.write_with_progress(device, offset, input)
            .map(|_| ())
            .map_err(|error| error.error)
    }

    pub fn write_with_progress(
        &self,
        device: &mut dyn BlockDevice,
        offset: u64,
        input: &[u8],
    ) -> Result<usize, BlockWriteError> {
        let mut done = 0;
        let result = (|| {
            let block_size = self.check(device, offset, input.len())?;
            if device.info().read_only {
                return Err(BlockError::WriteProtected);
            }
            let mut scratch = [0; MAX_BLOCK_SIZE];
            while done < input.len() {
                let position = offset + done as u64;
                let lba = self.start + position / block_size as u64;
                let within = (position % block_size as u64) as usize;
                let remaining = input.len() - done;
                if within == 0 && remaining >= block_size {
                    let count = (remaining / block_size).min(u32::MAX as usize) as u32;
                    let len = count as usize * block_size;
                    device.write_blocks(lba, count, &input[done..done + len])?;
                    done += len;
                } else {
                    device.read_block(lba, &mut scratch[..block_size])?;
                    let len = (block_size - within).min(remaining);
                    scratch[within..within + len].copy_from_slice(&input[done..done + len]);
                    device.write_block(lba, &scratch[..block_size])?;
                    done += len;
                }
            }
            Ok(())
        })();
        result.map(|()| done).map_err(|error| BlockWriteError {
            error,
            completed: done,
        })
    }
}
