//! Plan a whole-entry archive read with CacheThreadImpl::CalculateReadPages.

use super::{lifted, Memory};

pub const PAGE_SIZE: u64 = 0x10000;

#[derive(Debug, Eq, PartialEq)]
pub struct ReadPlan {
    pub offset: u64,
    pub bytes: u64,
    pub first_page: u64,
    pub last_page: u64,
}

/// Calculate the byte span and inclusive page range for a nonempty whole entry.
pub fn plan_read(offset: u64, packed: u32, unpacked: u32) -> Option<ReadPlan> {
    if packed == 0 || unpacked == 0 || offset.checked_add(u64::from(packed)).is_none() {
        return None;
    }

    const STACK: u32 = 0x600;
    const THREAD_OP: u32 = 0x800;
    const ARCHIVE_OP: u32 = 0x900;
    const RECORD: u32 = 0xa00;

    let mut mem = Memory::new(0x1000);
    mem.write32(STACK + 4, THREAD_OP);
    mem.write32(THREAD_OP, ARCHIVE_OP);
    mem.write32(THREAD_OP + 8, RECORD);
    // ArchiveOp starts at uncompressed offset zero with no active decompression stream.
    mem.write64(ARCHIVE_OP + 0x30, u64::MAX);
    mem.write32(ARCHIVE_OP + 0x38, unpacked);
    mem.write64(RECORD, offset);
    mem.write32(RECORD + 8, packed);
    mem.write32(RECORD + 0xc, unpacked);

    let ok = lifted::run(&mut mem, STACK, lifted::READ_PAGES, 0) as u8;
    if ok != 1 || mem.unsupported {
        return None;
    }

    let plan = ReadPlan {
        offset: offset.checked_add(mem.read64(THREAD_OP + 0xb0))?,
        bytes: mem.read64(THREAD_OP + 0xb8),
        first_page: mem.read64(THREAD_OP + 0x90),
        last_page: mem.read64(THREAD_OP + 0x98),
    };
    // Keep the guest's read plan within the host entry and its addressable pages.
    let end = plan.offset.checked_add(plan.bytes)?;
    if plan.offset != offset
        || plan.bytes != u64::from(packed)
        || plan.first_page != plan.offset / PAGE_SIZE
        || plan.last_page != (end - 1) / PAGE_SIZE
    {
        return None;
    }
    Some(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_stored_and_compressed_reads_across_page_boundaries() {
        assert_eq!(
            plan_read(0xffff, 2, 2),
            Some(ReadPlan {
                offset: 0xffff,
                bytes: 2,
                first_page: 0,
                last_page: 1,
            })
        );
        assert_eq!(
            plan_read(0x10000, 0x10000, 0x18000),
            Some(ReadPlan {
                offset: 0x10000,
                bytes: 0x10000,
                first_page: 1,
                last_page: 1,
            })
        );
    }

    #[test]
    fn propagates_64_bit_offset_carry() {
        assert_eq!(
            plan_read(0xffff_ffff, 2, 6),
            Some(ReadPlan {
                offset: 0xffff_ffff,
                bytes: 2,
                first_page: 0xffff,
                last_page: 0x10000,
            })
        );
        assert!(plan_read(u64::MAX, 1, 1).is_none());
    }
}
