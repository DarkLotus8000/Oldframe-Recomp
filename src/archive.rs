//! Read archive pages and select entry bytes with the translated cache thread routines.

use super::{lifted, Memory};
use std::io::{self, Read, Seek, SeekFrom};

pub const PAGE_SIZE: u64 = 0x10000;
const ARCHIVE_HANDLE: u32 = 1;
const SEMAPHORE_HANDLE: u32 = 2;
const IO_STACK: u32 = 0x600;
const CACHE_THREAD: u32 = 0xc00;
const IO_BUFFER: u32 = CACHE_THREAD + 0x110;
const IO_PENDING: u32 = 1;
const IO_READY: u32 = 3;

#[derive(Debug, Eq, PartialEq)]
pub struct ReadPlan {
    pub offset: u64,
    pub bytes: u64,
    pub first_page: u64,
    pub last_page: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct PageRequest {
    offset: u64,
    bytes: u32,
    destination: u32,
    overlapped: u32,
    completion: u32,
}

struct PageLoad {
    memory: Memory,
    request: PageRequest,
}

impl ReadPlan {
    /// Submit the planned pages and collect only the entry's byte span.
    pub fn read_from(&self, archive: &mut (impl Read + Seek)) -> io::Result<Vec<u8>> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid archive read plan");
        let end = self.offset.checked_add(self.bytes).ok_or_else(invalid)?;
        if self.bytes == 0
            || self.first_page != self.offset / PAGE_SIZE
            || self.last_page != (end - 1) / PAGE_SIZE
        {
            return Err(invalid());
        }
        let size = usize::try_from(self.bytes).map_err(|_| invalid())?;
        let mut result = Vec::with_capacity(size);
        for page in self.first_page..=self.last_page {
            let mut load = submit_page(page).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "archive read submission failed")
            })?;
            let transferred = load.read_from(archive)?.len();
            let bytes = load.select_entry_bytes(self, result.len() as u64, page, transferred)?;
            result.extend_from_slice(bytes);
        }
        if result.len() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive page spans did not cover the requested entry",
            ));
        }
        Ok(result)
    }
}

impl PageLoad {
    fn read_from(&mut self, archive: &mut (impl Read + Seek)) -> io::Result<&[u8]> {
        archive.seek(SeekFrom::Start(self.request.offset))?;
        let start = self.request.destination as usize;
        let mut available = &mut self.memory.bytes[start..start + self.request.bytes as usize];
        while !available.is_empty() {
            match archive.read(available) {
                Ok(0) => break,
                Ok(bytes) => available = &mut available[bytes..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let transferred = self.request.bytes - available.len() as u32;
        self.complete(0, transferred)
    }

    fn complete(&mut self, error: u32, transferred: u32) -> io::Result<&[u8]> {
        self.memory.write32(IO_STACK + 4, error);
        self.memory.write32(IO_STACK + 8, transferred);
        self.memory.write32(IO_STACK + 12, self.request.overlapped);
        lifted::run(&mut self.memory, IO_STACK, self.request.completion, 0);
        if self.memory.unsupported
            || !self.memory.completion_signaled
            || self.memory.read32(IO_BUFFER) != IO_READY
            || transferred > self.request.bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive read completion failed",
            ));
        }
        let start = self.request.destination as usize;
        Ok(&self.memory.bytes[start..start + transferred as usize])
    }

    fn select_entry_bytes(
        &mut self,
        plan: &ReadPlan,
        consumed: u64,
        page: u64,
        transferred: usize,
    ) -> io::Result<&[u8]> {
        const THREAD_OP: u32 = 0x3100;
        const RECORD: u32 = 0x3300;

        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid ready page span");
        let remaining = plan.bytes.checked_sub(consumed).ok_or_else(invalid)?;
        let mem = &mut self.memory;
        let file = mem.read32(IO_BUFFER + 0xc);
        mem.write32(THREAD_OP + 0x14, file);
        mem.write32(THREAD_OP + 0x18, RECORD);
        mem.write8(THREAD_OP + 0x1c, 1); // The operation holds buffer index zero.
        mem.write64(THREAD_OP + 0xa0, page);
        mem.write64(THREAD_OP + 0xc0, consumed);
        mem.write64(THREAD_OP + 0xc8, remaining);
        mem.write64(RECORD, plan.offset);
        mem.write32(IO_STACK + 8, THREAD_OP);
        mem.write32(IO_STACK + 12, 0);
        mem.selected_span = None;

        let ok = lifted::run(mem, IO_STACK, lifted::SELECT_PAGE_SPAN, CACHE_THREAD);
        let (begin, end) = mem.selected_span.ok_or_else(invalid)?;
        if ok != 1
            || mem.unsupported
            || begin < self.request.destination
            || end <= begin
            || end > self.request.destination + self.request.bytes
            || u64::from(end - begin) > remaining
        {
            return Err(invalid());
        }
        if (end - self.request.destination) as usize > transferred {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "archive ended inside the requested entry",
            ));
        }
        Ok(&mem.bytes[begin as usize..end as usize])
    }
}

fn submit_page(page: u64) -> Option<PageLoad> {
    const FILE_INFO: u32 = 0x900;
    const FILE: u32 = 0xa00;
    const SEMAPHORE_REF: u32 = 0xa80;
    const SEMAPHORE: u32 = 0xaa0;
    const DESTINATION: u32 = 0x4000;

    let offset = page.checked_mul(PAGE_SIZE)?;
    let mut mem = Memory::new(DESTINATION as usize + PAGE_SIZE as usize);
    mem.write32(IO_STACK + 4, IO_BUFFER);
    mem.write32(IO_STACK + 8, FILE_INFO);
    mem.write64(IO_STACK + 12, page);
    mem.write32(IO_BUFFER + 0x18, DESTINATION);
    mem.write32(FILE_INFO + 4, FILE);
    mem.write32(FILE + 0x60, ARCHIVE_HANDLE);
    mem.write32(CACHE_THREAD + 0x1910, SEMAPHORE_REF);
    mem.write32(SEMAPHORE_REF, SEMAPHORE);
    mem.write32(SEMAPHORE, SEMAPHORE_HANDLE);

    let ok = lifted::run(&mut mem, IO_STACK, lifted::START_IO, CACHE_THREAD);
    let request = mem.pending_read.take()?;
    if ok == 0 || mem.unsupported || request.offset != offset || mem.read32(IO_BUFFER) != IO_PENDING
    {
        return None;
    }
    Some(PageLoad {
        memory: mem,
        request,
    })
}

impl Memory {
    // Capture the game's ReadFileEx request. The caller supplies the page synchronously.
    pub(super) fn submit_archive_read(
        &mut self,
        file: u32,
        destination: u32,
        bytes: u32,
        overlapped: u32,
        completion: u32,
    ) -> u32 {
        if file != ARCHIVE_HANDLE
            || u64::from(bytes) != PAGE_SIZE
            || completion != lifted::READ_COMPLETE
            || overlapped != IO_BUFFER + 0x1c
            || self.pending_read.is_some()
            || self
                .bytes
                .get(destination as usize..)
                .is_none_or(|buf| buf.len() < bytes as usize)
            || self
                .bytes
                .get(overlapped as usize..)
                .is_none_or(|buf| buf.len() < 20)
            || self.read32(overlapped + 0x10) != CACHE_THREAD
        {
            return 0;
        }
        self.pending_read = Some(PageRequest {
            offset: self.read64(overlapped + 8),
            bytes,
            destination,
            overlapped,
            completion,
        });
        1
    }

    pub(super) fn release_io_semaphore(&mut self, handle: u32, count: u32, previous: u32) -> u32 {
        if handle != SEMAPHORE_HANDLE || count != 1 || previous != 0 || self.completion_signaled {
            return 0;
        }
        self.completion_signaled = true;
        1
    }
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

    #[test]
    fn submits_an_overlapped_read_above_four_gib() {
        let load = submit_page(0x10001).unwrap();
        assert_eq!(
            (load.request.offset, load.request.bytes),
            (0x0001_0001_0000, 0x10000)
        );
        assert!(submit_page(u64::MAX / PAGE_SIZE + 1).is_none());
    }

    #[test]
    fn reads_across_pages_and_requires_the_entry_bytes_at_eof() {
        let mut data = vec![0; PAGE_SIZE as usize + 1];
        data[PAGE_SIZE as usize - 1..].copy_from_slice(b"AB");
        let plan = plan_read(PAGE_SIZE - 1, 2, 2).unwrap();
        assert_eq!(plan.read_from(&mut io::Cursor::new(&data)).unwrap(), b"AB");
        data.pop();
        assert_eq!(
            plan.read_from(&mut io::Cursor::new(&data))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn callback_marks_the_pending_buffer_ready_and_signals_once() {
        let mut load = submit_page(0).unwrap();
        let start = load.request.destination as usize;
        load.memory.bytes[start..start + 2].copy_from_slice(b"AB");
        assert_eq!(load.complete(0, 2).unwrap(), b"AB");
        assert_eq!(load.memory.read32(IO_BUFFER), IO_READY);
        assert!(load.memory.completion_signaled);
        assert!(load.complete(0, 2).is_err());
    }

    #[test]
    fn callback_rejects_io_errors_and_oversized_transfers() {
        for (error, bytes) in [(23, 2), (0, PAGE_SIZE as u32 + 1)] {
            let mut load = submit_page(0).unwrap();
            assert!(load.complete(error, bytes).is_err());
            assert_eq!(load.memory.read32(IO_BUFFER), IO_PENDING);
            assert!(!load.memory.completion_signaled);
        }
    }

    #[test]
    fn selects_entry_bytes_on_a_ready_page_above_four_gib() {
        let page = 0x10001;
        let plan = plan_read((page - 1) * PAGE_SIZE + 0xfffe, 5, 5).unwrap();
        let mut load = submit_page(page).unwrap();
        let start = load.request.destination as usize;
        load.memory.bytes[start..start + 4].copy_from_slice(b"ABCX");
        let transferred = load.complete(0, 4).unwrap().len();
        assert_eq!(
            load.select_entry_bytes(&plan, 2, page, transferred)
                .unwrap(),
            b"ABC"
        );

        let mut pending = submit_page(page).unwrap();
        assert!(pending.select_entry_bytes(&plan, 2, page, 4).is_err());
        assert!(pending.memory.unsupported);
    }
}
