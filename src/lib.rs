//! A callable build of the U5.1 x86 cache decoder and stream routines.

pub mod archive;
pub mod startup;
mod lifted;

const STACK: u32 = 0x80;
const OUTPUT_SIZE: u32 = 0x100;
const INPUT: u32 = 0x4000;
const OUTPUT: u32 = INPUT + 0x10000;
const MAX_BLOCK: usize = u16::MAX as usize;
const INIT_STACK: u32 = 0x400;
const STREAM_STACK: u32 = 0x600;
const STREAM_OBJECT: u32 = 0x800;
const INPUT_RING: u32 = 0x900;
const OUTPUT_RING: u32 = 0xa00;
const ENTRY_OPTIONS: u32 = 0xb00;
const ENTRY_OUTPUT_SIZE: u32 = ENTRY_OPTIONS + 24;
const ENTRY_INPUT_SIZE: u32 = ENTRY_OUTPUT_SIZE + 4;
const SCRATCH: u32 = 0x24000;
const ENTRY_INPUT: u32 = SCRATCH + 0xc004;
const STREAM_BLOCK_LIMIT: usize = 0x4000;

struct Memory {
    bytes: Vec<u8>,
    decoded_lengths: Vec<u32>,
    scratch_allocated: bool,
    pending_read: Option<archive::PageRequest>,
    completion_signaled: bool,
    selected_span: Option<(u32, u32)>,
    unsupported: bool,
}

impl Memory {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            decoded_lengths: Vec::new(),
            scratch_allocated: false,
            pending_read: None,
            completion_signaled: false,
            selected_span: None,
            unsupported: false,
        }
    }

    fn read8(&self, addr: u32) -> u32 {
        u32::from(self.bytes[addr as usize])
    }

    fn read32(&self, addr: u32) -> u32 {
        let start = addr as usize;
        u32::from_le_bytes(self.bytes[start..start + 4].try_into().unwrap())
    }

    fn read64(&self, addr: u32) -> u64 {
        let start = addr as usize;
        u64::from_le_bytes(self.bytes[start..start + 8].try_into().unwrap())
    }

    fn write8(&mut self, addr: u32, value: u32) {
        self.bytes[addr as usize] = value as u8;
    }

    fn write32(&mut self, addr: u32, value: u32) {
        let start = addr as usize;
        self.bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write64(&mut self, addr: u32, value: u64) {
        let start = addr as usize;
        self.bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn move_bytes(&mut self, dest: u32, source: u32, size: u32) {
        self.bytes
            .copy_within(source as usize..(source + size) as usize, dest as usize);
    }

    fn allocate_scratch(&mut self, alignment: u32, size: u32) -> Option<u32> {
        if self.scratch_allocated
            || alignment != 16
            || size != 0xc004
            || self.bytes.len() < ENTRY_INPUT as usize
        {
            return None;
        }
        self.scratch_allocated = true;
        Some(SCRATCH)
    }

    fn query_memory(&mut self, addr: u32, info: u32, capacity: u32) -> u32 {
        const INFO_SIZE: u32 = 28;
        if addr as usize >= self.bytes.len()
            || capacity < INFO_SIZE
            || self
                .bytes
                .get(info as usize..)
                .is_none_or(|buf| buf.len() < INFO_SIZE as usize)
        {
            return 0;
        }
        // MEMORY_BASIC_INFORMATION32 for the host's ordinary read/write arena.
        let fields = [0, 0, 4, self.bytes.len() as u32, 0x1000, 4, 0x20000];
        for (index, value) in fields.into_iter().enumerate() {
            self.write32(info + index as u32 * 4, value);
        }
        INFO_SIZE
    }

    fn query_counter(&mut self, addr: u32) -> u32 {
        if self
            .bytes
            .get(addr as usize..)
            .is_none_or(|bytes| bytes.len() < 8)
        {
            return 0;
        }
        self.write64(addr, 0);
        1
    }
}

/// Decode one packed cache block and return the number of bytes written.
/// A return value of zero indicates failure. Block sizes use the cache's 16-bit lengths.
pub fn decode_block(packed: &[u8], output: &mut [u8]) -> usize {
    if packed.is_empty()
        || output.is_empty()
        || packed.len() > MAX_BLOCK
        || output.len() > MAX_BLOCK
    {
        return 0;
    }

    let mut memory = Memory::new(OUTPUT as usize + output.len());
    memory.bytes[INPUT as usize..][..packed.len()].copy_from_slice(packed);

    // The outer caller takes output, length pointer, input, and input length.
    // Returning to address zero exits the translated code.
    memory.write32(STACK, 0);
    memory.write32(STACK + 4, OUTPUT);
    memory.write32(STACK + 8, OUTPUT_SIZE);
    memory.write32(STACK + 12, INPUT);
    memory.write32(STACK + 16, packed.len() as u32);
    memory.write32(OUTPUT_SIZE, output.len() as u32);

    if lifted::run(&mut memory, STACK, lifted::CALLER, 0) as u8 == 0 {
        return 0;
    }
    let written = memory.read32(OUTPUT_SIZE) as usize;
    output[..written].copy_from_slice(&memory.bytes[OUTPUT as usize..][..written]);
    written
}

/// Decode one ordinary U5.1 cache frame, including its four-byte header.
/// A return value of zero indicates failure.
pub fn decode_frame(frame: &[u8], output: &mut [u8]) -> usize {
    decode_frame_at(frame, output, frame.len())
}

fn decode_frame_at(frame: &[u8], output: &mut [u8], contiguous: usize) -> usize {
    let Some((packed, decoded)) = frame_lengths(frame) else {
        return 0;
    };
    if frame.len() != packed + 4
        || decoded > output.len()
        || contiguous == 0
        || contiguous > frame.len()
    {
        return 0;
    }

    let mut memory = Memory::new((SCRATCH + 0xc004) as usize);
    let end = INPUT as usize + frame.len();
    let cursor = end - contiguous;
    memory.bytes[cursor..end].copy_from_slice(&frame[..contiguous]);
    memory.bytes[INPUT as usize..][..frame.len() - contiguous]
        .copy_from_slice(&frame[contiguous..]);

    if !initialize_stream(&mut memory) {
        return 0;
    }

    // Ring layout from the engine: begin, end, read, write, pending bytes.
    memory.write32(INPUT_RING, INPUT);
    memory.write32(INPUT_RING + 4, end as u32);
    memory.write32(INPUT_RING + 8, cursor as u32);
    memory.write32(INPUT_RING + 0xc, cursor as u32);
    memory.write32(INPUT_RING + 0x10, frame.len() as u32);
    memory.write32(INPUT_RING + 0x1c, frame.len() as u32);
    memory.write32(INPUT_RING + 0x20, frame.len() as u32);
    memory.write32(OUTPUT_RING, OUTPUT);
    memory.write32(OUTPUT_RING + 4, OUTPUT + decoded as u32);
    memory.write32(OUTPUT_RING + 8, OUTPUT);
    memory.write32(OUTPUT_RING + 0xc, OUTPUT);
    memory.write32(OUTPUT_RING + 0x20, decoded as u32);

    // The stream method takes its object in ECX and two ring pointers on the stack.
    memory.write32(STREAM_STACK + 4, INPUT_RING);
    memory.write32(STREAM_STACK + 8, OUTPUT_RING);
    lifted::run(&mut memory, STREAM_STACK, lifted::STREAM, STREAM_OBJECT);

    let expected_decode = (packed != decoded).then_some(decoded as u32);
    if memory.unsupported
        || memory.decoded_lengths != expected_decode.as_slice()
        || memory.read32(INPUT_RING + 0x10) != 0
        || memory.read32(STREAM_OBJECT + 0x48) != frame.len() as u32
        || memory.read32(OUTPUT_RING + 0x1c) != decoded as u32
    {
        return 0;
    }
    output[..decoded].copy_from_slice(&memory.bytes[OUTPUT as usize..][..decoded]);
    decoded
}

#[derive(Debug, Eq, PartialEq)]
pub struct FrameCounts {
    pub compressed: usize,
    pub stored: usize,
}

/// Decode a complete cache entry containing framed data. The output slice must
/// have the uncompressed length from the TOC. On failure it is left untouched.
pub fn decode_entry(packed: &[u8], output: &mut [u8]) -> Option<FrameCounts> {
    if packed.is_empty() || output.is_empty() {
        return None;
    }
    let input_len = u32::try_from(packed.len()).ok()?;
    let output_len = u32::try_from(output.len()).ok()?;
    let output_start = ENTRY_INPUT.checked_add(input_len)?.checked_add(15)? & !15;
    let memory_end = output_start.checked_add(output_len)?;

    // Validate the bounds of every frame before passing the entry to the game code.
    let mut remaining = packed;
    let mut total = 0usize;
    let mut expected_decodes = Vec::new();
    let mut stored = 0;
    while !remaining.is_empty() {
        let (size, decoded) = frame_lengths(remaining)?;
        remaining = remaining.get(size + 4..)?;
        total = total.checked_add(decoded)?;
        if total > output.len() {
            return None;
        }
        if size == decoded {
            stored += 1;
        } else {
            expected_decodes.push(decoded as u32);
        }
    }
    if total != output.len() {
        return None;
    }

    let mut memory = Memory::new(memory_end as usize);
    memory.bytes[ENTRY_INPUT as usize..][..packed.len()].copy_from_slice(packed);
    if !initialize_stream(&mut memory) {
        return None;
    }
    run_entry(&mut memory, output_start, output_len, input_len);

    if memory.unsupported
        || memory.decoded_lengths != expected_decodes
        || memory.read32(ENTRY_OUTPUT_SIZE) != output_len
        || memory.read32(ENTRY_INPUT_SIZE) != input_len
    {
        return None;
    }
    output.copy_from_slice(&memory.bytes[output_start as usize..]);
    Some(FrameCounts {
        compressed: expected_decodes.len(),
        stored,
    })
}

fn frame_lengths(frame: &[u8]) -> Option<(usize, usize)> {
    let [p0, p1, s0, s1, ..] = *frame else {
        return None;
    };
    let packed = usize::from(u16::from_be_bytes([p0, p1]));
    let decoded = usize::from(u16::from_be_bytes([s0, s1]));
    (packed > 0 && packed <= decoded && decoded <= STREAM_BLOCK_LIMIT).then_some((packed, decoded))
}

fn initialize_stream(memory: &mut Memory) -> bool {
    memory.write32(INIT_STACK + 4, 0); // The guest allocator is supplied by the host.
    let object = lifted::run(memory, INIT_STACK, lifted::CTOR, STREAM_OBJECT);
    object == STREAM_OBJECT && memory.scratch_allocated && !memory.unsupported
}

fn run_entry(memory: &mut Memory, output: u32, output_len: u32, input_len: u32) {
    memory.write32(ENTRY_OUTPUT_SIZE, output_len);
    memory.write32(ENTRY_INPUT_SIZE, input_len);
    // Zeroed format options select ordinary synchronous cache decompression.
    memory.write32(STREAM_STACK + 4, ENTRY_OPTIONS);
    memory.write32(STREAM_STACK + 8, output);
    memory.write32(STREAM_STACK + 12, ENTRY_OUTPUT_SIZE);
    memory.write32(STREAM_STACK + 16, ENTRY_INPUT);
    memory.write32(STREAM_STACK + 20, ENTRY_INPUT_SIZE);
    lifted::run(memory, STREAM_STACK, lifted::SETUP, STREAM_OBJECT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_each_literal_jump_target() {
        for count in 1..=32 {
            let expected: Vec<_> = (0..count).collect();
            let packed: Vec<_> = [count - 1]
                .into_iter()
                .chain(expected.iter().copied())
                .collect();
            let mut out = vec![0xff; count.into()];
            assert_eq!(decode_block(&packed, &mut out), out.len());
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn copies_overlapping_back_references() {
        let mut out = [0; 268];
        assert_eq!(
            decode_block(&[0, b'A', 0xe0, 255, 0, 0x20, 0], &mut out),
            268
        );
        assert!(out.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn rejects_truncated_input_and_output_overflow() {
        for packed in [&[1, b'A'][..], &[0, b'A', 0x20, 0], &[0x20, 0]] {
            let mut out = [0xff; 2];
            assert_eq!(decode_block(packed, &mut out), 0);
            assert_eq!(out, [0xff; 2]);
        }
    }

    #[test]
    fn caller_returns_the_written_length_through_its_pointer() {
        let mut out = [0xff; 4];
        assert_eq!(decode_block(&[0, b'A'], &mut out), 1);
        assert_eq!(out, [b'A', 0xff, 0xff, 0xff]);
    }

    #[test]
    fn stream_reads_stored_and_compressed_frames_across_the_ring_boundary() {
        for frame in [
            &[0, 6, 0, 6, b'A', b'A', b'A', b'A', b'A', b'A'][..],
            &[0, 4, 0, 6, 0, b'A', 0x60, 0],
        ] {
            for contiguous in 1..=frame.len() {
                let mut out = [0; 6];
                assert_eq!(
                    decode_frame_at(frame, &mut out, contiguous),
                    out.len(),
                    "split at {contiguous}"
                );
                assert_eq!(&out, b"AAAAAA");
            }
        }
    }

    #[test]
    fn stream_rejects_incomplete_frames_and_failed_decodes() {
        for frame in [&[0, 4, 0, 6, 0, b'A', 0x60][..], &[0, 2, 0, 6, 0x20, 0]] {
            let mut out = [0xff; 6];
            assert_eq!(decode_frame(frame, &mut out), 0);
            assert_eq!(out, [0xff; 6]);
        }
    }

    #[test]
    fn entry_reuses_the_stream_across_stored_and_compressed_frames() {
        let packed = [
            b"\x00\x03\x00\x03RAW".as_slice(),
            b"\x00\x04\x00\x06\x00A\x60\x00",
            b"\x00\x02\x00\x02zz",
        ]
        .concat();
        let mut out = [0; 11];
        assert_eq!(
            decode_entry(&packed, &mut out),
            Some(FrameCounts {
                compressed: 1,
                stored: 2
            })
        );
        assert_eq!(&out, b"RAWAAAAAAzz");
    }

    #[test]
    fn entry_rejects_a_failed_frame_even_if_a_later_frame_decodes() {
        let packed = [
            b"\x00\x02\x00\x06\x20\x00".as_slice(),
            b"\x00\x04\x00\x06\x00A\x60\x00",
        ]
        .concat();
        let mut out = [0xff; 12];
        assert_eq!(decode_entry(&packed, &mut out), None);
        assert_eq!(out, [0xff; 12]);
        assert_eq!(decode_entry(&packed[..packed.len() - 1], &mut out), None);
    }

    #[test]
    fn game_constructs_the_stream_and_selects_direct_output_for_writable_memory() {
        let frame = b"\x00\x04\x00\x06\x00A\x60\x00";
        let output = ENTRY_INPUT + 16;
        let mut memory = Memory::new(output as usize + 6);
        memory.bytes[ENTRY_INPUT as usize..][..frame.len()].copy_from_slice(frame);
        assert!(initialize_stream(&mut memory));
        assert_eq!(memory.read32(STREAM_OBJECT + 4), SCRATCH + 0x8000);
        assert_eq!(memory.read8(STREAM_OBJECT + 0x1c), 1);
        run_entry(&mut memory, output, 6, frame.len() as u32);
        assert!(!memory.unsupported);
        assert_eq!(memory.read8(STREAM_OBJECT + 0x1c), 0);
        assert_eq!(memory.read32(ENTRY_OUTPUT_SIZE), 6);
        assert_eq!(memory.read32(ENTRY_INPUT_SIZE), frame.len() as u32);
        assert_eq!(&memory.bytes[output as usize..], b"AAAAAA");
    }
}
