//! Original PE/CRT startup translated to Rust, with deterministic Win32 fixtures.
#[path = "startup_lifted.rs"]
mod translated;
const COOKIE: u32 = 0x1310b30;
const INITIAL_STACK: u32 = 0x20000;
const ENTROPY_XOR: u32 = 0x11223344 ^ 0x55667788 ^ 0x1234 ^ 0x5678 ^ 0x01020304 ^ 0x05060708;

struct Memory {
    bytes: Vec<u8>,
    entropy: u32,
    calls: Vec<u32>,
    stack: u32,
    frame: u32,
    fs_base: u32,
    eax: u32,
    heap_result: u32,
    fls_mask: u32,
    module_present: bool,
    tls_index: u32,
    tls_success: bool,
    tls_value: u32,
    locks: Vec<u32>,
    lock_failure: usize,
    tls_allocations: u32,
    thread_slot_failure: bool,
    allocation_failures: usize,
    allocation_calls: usize,
    heap_next: u32,
    thread_value: u32,
    thread_set_success: bool,
    allocation_fail_at: usize,
    stdio_variant: u32,
}
impl Memory {
    fn read8(&self, addr: u32) -> u32 {
        self.bytes[addr as usize] as u32
    }
    fn write8(&mut self, addr: u32, value: u32) {
        self.bytes[addr as usize] = value as u8;
    }
    fn write16(&mut self, addr: u32, value: u32) {
        self.bytes[addr as usize..addr as usize + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    fn read16(&self, addr: u32) -> u32 {
        u16::from_le_bytes(
            self.bytes[addr as usize..addr as usize + 2]
                .try_into()
                .unwrap(),
        ) as u32
    }
    fn read32(&self, addr: u32) -> u32 {
        u32::from_le_bytes(
            self.bytes[addr as usize..addr as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn write32(&mut self, addr: u32, value: u32) {
        self.bytes[addr as usize..addr as usize + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn import(&mut self, slot: u32, stack: u32) -> Result<u32, String> {
        self.calls.push(slot);
        match slot {
            0x10a7268 | 0x10a709c => {
                let ptr = self.read32(stack);
                let (low, high) = if slot == 0x10a7268 {
                    (0x55667788, 0x11223344)
                } else {
                    (0x05060708, 0x01020304)
                };
                self.write32(ptr, low);
                self.write32(ptr + 4, high);
                Ok(1)
            }
            0x10a7138 => Ok(0x1234),
            0x10a7154 => Ok(0x5678),
            0x10a7304 => Ok(self.entropy ^ ENTROPY_XOR),
            0x10a7280 => {
                let ptr = self.read32(stack);
                self.bytes[ptr as usize..ptr as usize + 68].fill(0);
                self.write32(ptr, 68);
                if self.stdio_variant == 28 {
                    self.write16(ptr + 50, 1);
                }
                if self.stdio_variant == 33 {
                    self.write16(ptr + 50, 1);
                    self.write32(ptr + 52, 0x18000);
                }
                Ok(0)
            }
            0x10a727c => {
                let args = (0..4)
                    .map(|n| self.read32(stack + 4 * n))
                    .collect::<Vec<_>>();
                if args != [0, 1, 0, 0] {
                    return Err(format!("unexpected HeapSetInformation arguments {args:?}"));
                }
                Ok(1)
            }
            0x10a7300 => {
                if (0..3)
                    .map(|n| self.read32(stack + 4 * n))
                    .collect::<Vec<_>>()
                    != [0, 0x1000, 0]
                {
                    return Err("unexpected HeapCreate arguments".into());
                }
                Ok(self.heap_result)
            }
            0x10a70a4 => {
                let ptr = self.read32(stack);
                let name = (0..13)
                    .map(|n| self.read16(ptr + 2 * n) as u16)
                    .collect::<Vec<_>>();
                if String::from_utf16_lossy(&name) != "KERNEL32.DLL\0" {
                    return Err("unexpected module name".into());
                }
                Ok(if self.module_present { 0x70000000 } else { 0 })
            }
            0x10a70a8 => {
                if self.read32(stack) != 0x70000000 {
                    return Err("unexpected module token".into());
                }
                let ptr = self.read32(stack + 4) as usize;
                let len = self.bytes[ptr..]
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or("unterminated API name")?;
                let name = &self.bytes[ptr..ptr + len];
                let index = [
                    b"FlsAlloc".as_slice(),
                    b"FlsGetValue",
                    b"FlsSetValue",
                    b"FlsFree",
                ]
                .iter()
                .position(|candidate| *candidate == name)
                .ok_or("unexpected dynamic API name")?;
                Ok(if self.fls_mask & (1 << index) != 0 {
                    0x50000 + index as u32 * 16
                } else {
                    0
                })
            }
            0x10a7088 => {
                let result = if self.tls_allocations == 0 {
                    self.tls_index
                } else if self.thread_slot_failure {
                    0xffffffff
                } else {
                    8
                };
                self.tls_allocations += 1;
                Ok(result)
            }
            0x10a72f0 => {
                if self.read32(stack) == 8 {
                    if self.thread_set_success {
                        self.thread_value = self.read32(stack + 4);
                    }
                    return Ok(u32::from(self.thread_set_success));
                }
                if self.read32(stack) != self.tls_index {
                    return Err("unexpected TLS index".into());
                }
                if self.tls_success {
                    self.tls_value = self.read32(stack + 4);
                }
                Ok(u32::from(self.tls_success))
            }
            0x10a7284 | 0x10a7288 => Ok(self.read32(stack) ^ 0xa5a55a5a),
            0x50000 => {
                if self.read32(stack) != 0xf22d03 {
                    return Err("unexpected FLS cleanup callback".into());
                }
                Ok(if self.thread_slot_failure {
                    0xffffffff
                } else {
                    9
                })
            }
            0x50020 => {
                if self.read32(stack) != 9 {
                    return Err("unexpected FLS index".into());
                }
                if self.thread_set_success {
                    self.thread_value = self.read32(stack + 4);
                }
                Ok(u32::from(self.thread_set_success))
            }
            0x10a72f8 => {
                let ptr = self.read32(stack);
                let value = self.read32(ptr).wrapping_add(1);
                self.write32(ptr, value);
                Ok(value)
            }
            0x10a70c8 | 0x10a70c4 => {
                let ptr = self.read32(stack);
                if !self.locks.contains(&ptr) {
                    return Err(format!("uninitialized critical section {ptr:#x}"));
                }
                let entering = slot == 0x10a70c8;
                let delta = if entering { 1 } else { u32::MAX };
                if !entering && self.read32(ptr + 8) == 0 {
                    return Err("unbalanced critical section release".into());
                }
                self.write32(ptr + 4, self.read32(ptr + 4).wrapping_add(delta));
                self.write32(ptr + 8, self.read32(ptr + 8).wrapping_add(delta));
                self.write32(ptr + 12, if self.read32(ptr + 8) == 0 { 0 } else { 0x5678 });
                Ok(0)
            }
            0x10a7328 => {
                if self.read32(stack) != self.heap_result || self.read32(stack + 4) != 8 {
                    return Err("unexpected HeapAlloc handle or flags".into());
                }
                self.allocation_calls += 1;
                if self.allocation_calls <= self.allocation_failures
                    || self.allocation_calls == self.allocation_fail_at
                {
                    return Ok(0);
                }
                let size = self.read32(stack + 8);
                let ptr = self.heap_next;
                let end = ptr.checked_add(size).ok_or("guest heap size overflow")?;
                if end > 0x100000 {
                    return Err("guest heap arena exhausted".into());
                }
                self.bytes[ptr as usize..end as usize].fill(0);
                self.heap_next = (end + 15) & !15;
                Ok(ptr)
            }
            0x10a71d8 => Ok(0), // Deterministic Sleep fixture; recorded in the API trace.
            0x10a72d4 => {
                let index = match self.read32(stack) {
                    0xfffffff6 => 0,
                    0xfffffff5 => 1,
                    0xfffffff4 => 2,
                    _ => return Err("unexpected std handle selector".into()),
                };
                Ok(if self.stdio_variant == 29 {
                    0
                } else if self.stdio_variant == 30 {
                    0xffffffff
                } else {
                    0x90000 + index * 4
                })
            }
            0x10a72d8 => {
                let index = match self.read32(stack) {
                    0x90000 => 0,
                    0x90004 => 1,
                    0x90008 => 2,
                    _ => return Err("unexpected std handle token".into()),
                };
                Ok(if self.stdio_variant == 31 {
                    0
                } else {
                    [2, 3, 1][index]
                })
            }
            0x10a72d0 => {
                if self.read32(stack) != 32 {
                    return Err("unexpected handle count".into());
                }
                Ok(32)
            }
            0x10a71a4 => {
                let ptr = self.read32(stack);
                if self.read32(stack + 4) != 4000 {
                    return Err("unexpected lock spin count".into());
                }
                self.locks.push(ptr);
                if self.locks.len() == self.lock_failure {
                    return Ok(0);
                }
                for (n, value) in [0, 0xffffffff, 0, 0, 0, 4000].into_iter().enumerate() {
                    self.write32(ptr + n as u32 * 4, value);
                }
                Ok(1)
            }
            _ => Err(format!("unresolved startup import slot {slot:#x}")),
        }
    }
}

/// Run the actual PE entry through its first call and stop before CRT startup.
/// Inputs are reproducible fixtures, not a production security-cookie source.
pub fn checkpoint(initial: u32, entropy: u32) -> Result<(u32, u32, u32, Vec<u32>), String> {
    let mut m = Memory {
        bytes: vec![0; 0x1400000],
        entropy,
        calls: Vec::new(),
        stack: 0,
        frame: 0,
        fs_base: 0x10000,
        eax: 0,
        heap_result: 0x60000,
        fls_mask: 15,
        module_present: true,
        tls_index: 7,
        tls_success: true,
        tls_value: 0,
        locks: Vec::new(),
        lock_failure: usize::MAX,
        tls_allocations: 0,
        thread_slot_failure: false,
        allocation_failures: 0,
        allocation_calls: 0,
        heap_next: 0x80000,
        thread_value: 0,
        thread_set_success: true,
        allocation_fail_at: usize::MAX,
        stdio_variant: 0,
    };
    m.write32(COOKIE, initial);
    m.write32(COOKIE + 4, 0xdeadbeef);
    translated::run(&mut m, 0xf17bd9)?;
    if m.stack != INITIAL_STACK {
        return Err(format!("startup stack imbalance: {:#x}", m.stack));
    }
    Ok((m.read32(COOKIE), m.read32(COOKIE + 4), m.stack, m.calls))
}

pub fn run_checkpoints() -> Result<(), String> {
    for (initial, entropy) in [
        (0xbb40e64e, 0x12345678),
        (0x87654321, 0x12345678),
        (0xbb40e64e, 0xbb40e64e),
        (0xbb40e64e, 0x1234),
        (0x1234, 0),
        (0xbb40e64e, 0xffff0000),
    ] {
        let (cookie, complement, stack, calls) = checkpoint(initial, entropy)?;
        if cookie == 0xbb40e64e || cookie & 0xffff0000 == 0 || complement != !cookie {
            return Err("invalid cookie state at checkpoint".into());
        }
        println!("STARTUP_COOKIE_READY initial={initial:08x} entropy={entropy:08x} cookie={cookie:08x} complement={complement:08x} stack={stack:08x} calls={}",
                 calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    run_seh_checkpoints()?;
    run_runtime_checkpoints()?;
    run_allocator_checkpoints()?;
    run_locale_checkpoints()?;
    Ok(())
}

fn seh_memory(variant: u32, previous: u32) -> Memory {
    let mut m = Memory {
        bytes: vec![0; 0x1400000],
        entropy: 0x12345678,
        calls: Vec::new(),
        stack: 0,
        frame: 0,
        fs_base: 0x10000,
        eax: 0,
        heap_result: 0x60000,
        fls_mask: 15,
        module_present: true,
        tls_index: 7,
        tls_success: true,
        tls_value: 0,
        locks: Vec::new(),
        lock_failure: usize::MAX,
        tls_allocations: 0,
        thread_slot_failure: false,
        allocation_failures: 0,
        allocation_calls: 0,
        heap_next: 0x80000,
        thread_value: 0,
        thread_set_success: true,
        allocation_fail_at: usize::MAX,
        stdio_variant: 0,
    };
    m.bytes[0x400000..0x400000 + translated::PE_HEADERS.len()]
        .copy_from_slice(translated::PE_HEADERS);
    for &(addr, offset, size) in translated::DATA_RANGES {
        m.bytes[addr as usize..addr as usize + size]
            .copy_from_slice(&translated::IMAGE_DATA[offset..offset + size]);
    }
    m.write32(COOKIE, 0xbb40e64e);
    m.write32(COOKIE + 4, 0xdeadbeef);
    m.write32(m.fs_base, previous);
    m.write32(0x1359dbc, variant & 1);
    for slot in [
        0x10a70a8, 0x10a72ec, 0x10a72f0, 0x10a72f4, 0x10a7284, 0x10a7288, 0x10a72f8,
    ] {
        m.write32(slot, slot);
    }
    let pe = 0x400000 + m.read32(0x40003c);
    match variant {
        1 => m.write32(0x400000, 0),
        2 => m.write32(pe, 0),
        3 => m.write32(pe + 24, 0x20b),
        4 => m.write32(pe + 0x74, 14),
        5 => m.write32(pe + 0xe8, 0x1000),
        _ => (),
    }
    m
}

fn run_seh_checkpoints() -> Result<(), String> {
    for stop in [0xf17be5, 0xf17c4d] {
        for variant in 0..6 {
            let previous = if variant & 1 == 0 {
                0xffffffff
            } else {
                0x18000
            };
            let mut m = seh_memory(variant, previous);
            translated::run(&mut m, stop)?;
            let head = m.read32(m.fs_base);
            if head != m.frame - 0x10
                || m.read32(head) != previous
                || m.read32(head + 4) != 0xf19540
            {
                return Err("SEH registration chain mismatch".into());
            }
            let snapshot = m.bytes[0x1ff70..0x20000]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            println!("STARTUP_FRAME_READY stop={stop:08x} variant={variant:08x} previous={previous:08x} stack={:08x} frame={:08x} head={head:08x} snapshot={snapshot} calls={}", m.stack, m.frame,
                m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
        }
    }
    Ok(())
}

fn run_runtime_checkpoints() -> Result<(), String> {
    for variant in 0..34 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = if variant == 0 { 0 } else { 0x60000 };
        m.module_present = variant != 1;
        m.fls_mask = if variant >= 8 {
            if [9, 16, 18, 22, 27].contains(&variant) {
                0
            } else {
                15
            }
        } else if variant < 3 {
            15
        } else if variant == 3 {
            0
        } else {
            15 ^ (1 << (variant - 4))
        };
        m.tls_index = if variant == 10 { 0xffffffff } else { 7 };
        m.tls_success = variant != 11;
        m.thread_slot_failure = variant == 17 || variant == 18;
        m.allocation_failures = if variant == 20 { 1 } else { 0 };
        m.thread_set_success = variant != 23;
        m.allocation_fail_at = if variant == 25 { 2 } else { usize::MAX };
        m.stdio_variant = variant;
        m.lock_failure = if variant == 13 {
            1
        } else if variant == 14 {
            7
        } else if variant == 32 {
            15
        } else {
            usize::MAX
        };
        let stop = if variant == 33 {
            0xf21e59
        } else if variant >= 26 {
            0xf17c7c
        } else if variant == 25 {
            0xf17c7c
        } else if variant == 24 {
            0xf21e42
        } else if variant == 23 {
            0xf23011
        } else if variant >= 21 {
            0xf17c63
        } else if variant == 20 {
            0xf23011
        } else if variant == 19 {
            0xf22fe1
        } else if variant >= 17 {
            0xf23011
        } else if variant >= 15 {
            0xf22fcd
        } else if variant >= 12 {
            0xf22faa
        } else if variant >= 10 {
            0xf23016
        } else if variant >= 8 {
            0xf22fa5
        } else if variant == 0 {
            0xf17c56
        } else if variant == 1 {
            0xf22eb4
        } else {
            0xf22f41
        };
        translated::run(&mut m, stop)?;
        let state = [
            m.eax,
            m.read32(0x1358c78),
            m.read32(0x1358c68),
            m.read32(0x1358c6c),
            m.read32(0x1358c70),
            m.read32(0x1358c74),
            m.read32(0x1310ef4),
            m.tls_value,
            m.read32(0x1358d7c),
            m.read32(0x1358048),
            m.read32(0x1358c7c),
            m.read32(0x1358d90),
            m.read32(0x1358d68),
            m.read32(0x1358d6c),
            m.read32(0x1358d70),
            m.read32(0x1358d74),
            m.read32(0x1358d8c),
            m.read32(0x1310ef0),
            m.heap_next,
            m.allocation_calls as u32,
            m.thread_value,
            m.read32(m.fs_base),
            m.read32(0x1359ca0),
            m.read32(0x1359c88),
        ]
        .iter()
        .map(|n| format!("{n:08x}"))
        .collect::<Vec<_>>()
        .join(",");
        let locks = m.bytes[0x1310d90..0x1310eb0]
            .iter()
            .chain(m.bytes[0x13580b8..0x13580b8 + 36 * 24].iter())
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let thread = m.bytes[0x80000..0x80214]
            .iter()
            .chain(m.bytes[0x1310f30..0x13116a0].iter())
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let files = m.bytes[0x80220..0x80a20]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        println!("STARTUP_RUNTIME_READY variant={variant:08x} stop={stop:08x} stack={:08x} frame={:08x} state={state} locks={locks} thread={thread} files={files} calls={}", m.stack, m.frame,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_allocator_checkpoints() -> Result<(), String> {
    // start, count, size, failures, retry timeout, new-handler flag, stop
    for (variant, (start, count, size, failures, retry, handler, stop)) in [
        (0xf3038d, 0, 123, 0, 0, 0, 0),
        (0xf3038d, 1, 32, 1, 0, 0, 0),
        (0xf3038d, 0xffffffff, 2, 0, 0, 0, 0xf303a5),
        (0xf3038d, 1, 32, 1, 0, 1, 0xf303e3),
        (0xf22053, 2, 16, 1, 2000, 0, 0),
        (0xf22053, 2, 16, 2, 1, 0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let mut m = seh_memory(0, 0xffffffff);
        m.allocation_failures = failures;
        m.write32(0x1358c78, m.heap_result);
        m.write32(0x1358208, retry);
        m.write32(0x1358d80, handler);
        m.bytes[0x80000..0x80400].fill(0xa5);
        for (n, value) in [0, count, size, 0x18000].into_iter().enumerate() {
            m.write32(INITIAL_STACK + n as u32 * 4, value);
        }
        translated::run_from(&mut m, start, stop)?;
        let heap = m.bytes[0x80000..0x80400]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        println!("STARTUP_ALLOCATOR_READY variant={variant} eax={:08x} stack={:08x} error={:08x} next={:08x} attempts={} heap={heap} calls={}",
            m.eax, m.stack, m.read32(0x18000), m.heap_next, m.allocation_calls,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_locale_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    let object = 0x70000;
    m.write32(object, 3);
    for (n, offset) in [0xb0, 0xb8, 0xb4, 0xc0].into_iter().enumerate() {
        let ptr = 0x70800 + n as u32 * 4;
        m.write32(object + offset, ptr);
        m.write32(ptr, 42);
    }
    for n in 0..6 {
        let field = object + 0x50 + n * 16;
        m.write32(field - 8, if n == 0 { 0x1311454 } else { 0 });
        m.write32(field - 4, if n == 2 { 0 } else { 1 });
        m.write32(field, if n == 1 { 0 } else { 0x70820 + n * 8 });
        m.write32(field + 4, if n == 3 { 0 } else { 0x70824 + n * 8 });
    }
    m.write32(object + 0xd4, 0x70a00);
    m.write32(INITIAL_STACK, 0);
    m.write32(INITIAL_STACK + 4, object);
    translated::run_from(&mut m, 0xf25870, 0)?;
    let data = m.bytes[0x70000..0x71000]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!(
        "STARTUP_LOCALE_READY eax={:08x} stack={:08x} data={data} calls={}",
        m.eax,
        m.stack,
        m.calls
            .iter()
            .map(|slot| format!("{slot:08x}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookie_initialization_branches() {
        for (initial, entropy, expected, count) in [
            (0xbb40e64e, 0x12345678, 0x12345678, 5),
            (0x87654321, 0, 0x87654321, 0),
            (0xbb40e64e, 0xbb40e64e, 0xbb40e64f, 5),
            (0xbb40e64e, 0x1234, 0x57351234, 5),
            (0x1234, 0, 0x47110000, 5),
        ] {
            let (cookie, complement, stack, calls) = checkpoint(initial, entropy).unwrap();
            assert_eq!(
                (cookie, complement, stack, calls.len()),
                (expected, !expected, INITIAL_STACK, count)
            );
        }
    }
}
