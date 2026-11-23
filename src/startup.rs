//! Original PE/CRT startup translated to Rust, with deterministic Win32 fixtures.
#[path = "startup_lifted.rs"]
mod translated;
const COOKIE: u32 = 0x1310b30;
// Reversible stand-in used only by the deterministic startup fixture.
const STARTUP_FIXTURE_POINTER_XOR: u32 = 0xa5a55a5a;
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
    environment_variant: u32,
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
    fn write64(&mut self, addr: u32, value: u64) {
        self.bytes[addr as usize..addr as usize + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn read64(&self, addr: u32) -> u64 {
        u64::from_le_bytes(self.bytes[addr as usize..addr as usize + 8].try_into().unwrap())
    }
    fn read128(&self, addr: u32) -> u128 {
        u128::from_le_bytes(self.bytes[addr as usize..addr as usize + 16].try_into().unwrap())
    }
    fn write128(&mut self, addr: u32, value: u128) {
        self.bytes[addr as usize..addr as usize + 16].copy_from_slice(&value.to_le_bytes());
    }
    fn import(&mut self, slot: u32, stack: u32, ecx: u32) -> Result<u32, String> {
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
                let module = self.read32(stack);
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
                    b"GetFinalPathNameByHandleW",
                ]
                .iter()
                .position(|candidate| *candidate == name)
                .ok_or("unexpected dynamic API name")?;
                if (index == 4 && module != 0x90000)
                    || (index != 4 && module != 0x70000000)
                {
                    return Err("unexpected module token".into());
                }
                Ok(if index == 4 || self.fls_mask & (1 << index) != 0 {
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
            0x10a7284 | 0x10a7288 => Ok(self.read32(stack) ^ STARTUP_FIXTURE_POINTER_XOR),
            0xf26500 => Ok(1),
            0xf18111 => Ok(0),
            0x10a7308 => Ok(1),
            0x10a7160 => Ok(0),
            0x41d560 => {
                let input = self.read32(stack);
                let value = match (ecx, input) {
                    (0x131d5f0, 0x3f800000) => 42,
                    (0x1327590, 0x3f000000) => 21,
                    (0x1332468, 0x3fc00000) => 63,
                    _ => {
                    return Err(format!("unexpected duration initializer {ecx:#x}, {:#x}", self.read32(stack)));
                    }
                };
                self.write64(ecx, value);
                self.write8(ecx + 8, 0);
                Ok(ecx)
            }
            0xf23cff => Ok(128),
            0xf2209f => {
                let old = self.read32(stack);
                let size = self.read32(stack + 4);
                if size != 256 { return Err(format!("unexpected atexit growth size {size}")); }
                let new = self.heap_next;
                let end = new.checked_add(size).ok_or("atexit growth overflow")?;
                if end > 0x100000 { return Err("guest heap arena exhausted during atexit growth".into()); }
                self.bytes.copy_within(old as usize..old as usize + 128, new as usize);
                self.bytes[new as usize + 128..end as usize].fill(0);
                self.heap_next = (end + 15) & !15;
                Ok(new)
            }
            0x4132a0 => {
                let descriptor = self.read32(stack);
                let size = self.read32(stack + 4);
                let count = self.read32(stack + 8);
                if ![0x128f238, 0x129a4c8, 0x12a18a8, 0x1313c98, 0x12a79f0, 0x12cacec].contains(&descriptor) || count != 1 || size == 0
                    || (descriptor == 0x129a4c8 && size != 8)
                    || (descriptor == 0x12a18a8 && size != 0x30)
                    || (descriptor == 0x1313c98 && size != 0x38)
                    || (descriptor == 0x12a79f0 && size != 0x30)
                    || (descriptor == 0x12cacec && ![8, 44].contains(&size))
                {
                    return Err(format!("unexpected game allocation {descriptor:#x}, {size}, {count}"));
                }
                if descriptor == 0x129a4c8 && self.allocation_fail_at == 0
                {
                    return Ok(0);
                }
                let total = size.checked_mul(count).ok_or("game allocation overflow")?;
                let ptr = self.heap_next;
                let end = ptr.checked_add(total).ok_or("guest heap size overflow")?;
                if end > 0x100000 { return Err("guest heap arena exhausted".into()); }
                self.bytes[ptr as usize..end as usize].fill(0);
                self.heap_next = (end + 15) & !15;
                Ok(ptr)
            }
            0x418e10 => {
                if self.read32(stack) != 0x10abd8c {
                    return Err("unexpected library name".into());
                }
                Ok(0x90000)
            }
            0x43fd40 => {
                let destination = self.read32(stack);
                let capacity = self.read32(stack + 4) as usize;
                let source = self.read32(stack + 8);
                if capacity == 0 { return Ok(0); }
                let source_start = source as usize;
                let length = self.bytes[source_start..]
                    .iter().position(|byte| *byte == 0)
                    .ok_or("unterminated bounded-copy input")?
                    .min(capacity - 1);
                self.bytes.copy_within(source_start..source_start + length, destination as usize);
                self.write8(destination + length as u32, 0);
                Ok(length as u32)
            }
            0x4a4ec0 => {
                let output = self.read32(stack);
                let begin = self.read32(stack + 4);
                let end = self.read32(stack + 8);
                let key = self.read32(self.read32(stack + 12));
                let mut low = 0;
                let mut high = end.wrapping_sub(begin) / 4;
                while low < high {
                    let mid = low + (high - low) / 2;
                    let candidate = self.read32(begin + mid * 4);
                    let compare = |left: u32, right: u32, bytes: &[u8]| {
                        let left_start = left as usize;
                        let right_start = right as usize;
                        let left_len = bytes[left_start..].iter().position(|byte| *byte == 0).unwrap();
                        let right_len = bytes[right_start..].iter().position(|byte| *byte == 0).unwrap();
                        bytes[left_start..left_start + left_len].cmp(&bytes[right_start..right_start + right_len])
                    };
                    let first = compare(self.read32(candidate + 4), self.read32(key + 4), &self.bytes);
                    let ordering = if first == std::cmp::Ordering::Equal {
                        compare(self.read32(candidate + 8), self.read32(key + 8), &self.bytes)
                    } else { first };
                    if ordering == std::cmp::Ordering::Less { low = mid + 1; } else { high = mid; }
                }
                self.write32(output, begin + low * 4);
                Ok(output)
            }
            0x460ac0 => {
                let position = self.read32(stack);
                let count = self.read32(stack + 4);
                let source = self.read32(stack + 8);
                let begin = self.read32(ecx);
                let end = self.read32(ecx + 4);
                let capacity = self.read32(ecx + 8);
                if ecx != self.read32(0x131c580) || position < begin || position > end
                    || (position - begin) % 4 != 0 || count != 1 || end + 4 > capacity {
                    return Err(format!("unexpected registry-vector insertion {ecx:#x}, {position:#x}, {count}"));
                }
                self.bytes.copy_within(position as usize..end as usize, position as usize + 4);
                self.write32(position, self.read32(source));
                self.write32(ecx + 4, end + 4);
                if begin == 0 { return Err("registry vector has no storage".into()); }
                Ok(0)
            }
            0x43eb90 => {
                let object = self.read32(stack);
                let name = self.read32(stack + 4);
                if ecx != self.read32(0x131ad88)
                    || ![0x131ad98, 0x131ae20, 0x131aec0, 0x131af48].contains(&object)
                    || ![0x10b0a38, 0x10b07d4].contains(&name)
                {
                    return Err(format!("unexpected manager registration {ecx:#x}, {object:#x}, {name:#x}"));
                }
                let mut item = self.read32(ecx);
                let cursor = self.read32(ecx + 4);
                while item < cursor {
                    let node = self.read32(item);
                    if self.read32(node + 0x14) == name {
                        self.write32(object + 0x10, node);
                        return Ok(0);
                    }
                    item += 4;
                }
                let node = self.heap_next;
                let end = node + 0x20;
                self.bytes[node as usize..end as usize].fill(0);
                self.write32(node + 0x14, name);
                self.write32(node + 0x1c, 0xffffffff);
                if cursor == 0 || cursor + 4 > self.read32(ecx + 8) {
                    return Err("manager vector was not initialized".into());
                }
                self.write32(cursor, node);
                self.write32(ecx + 4, cursor + 4);
                self.write32(object + 0x10, node);
                self.heap_next = (end + 15) & !15;
                Ok(0)
            }
            0x44aae0 => {
                let position = self.read32(stack);
                let count = self.read32(stack + 4);
                let source = self.read32(stack + 8);
                let begin = self.read32(ecx);
                let end = self.read32(ecx + 4);
                let capacity = self.read32(ecx + 8);
                if ecx != 0x131b1f0 || position != end || count != 1 || end != capacity {
                    return Err(format!("unexpected singleton vector insertion {ecx:#x}, {position:#x}, {count}, {source:#x}"));
                }
                let existing = if begin == 0 { 0 } else { end.wrapping_sub(begin) / 4 };
                let ptr = self.heap_next;
                let length = existing + 1;
                let capacity_items = if existing >= 2 {
                    length.checked_mul(2).ok_or("vector capacity overflow")?
                } else {
                    length
                };
                let allocation_end = ptr.checked_add(capacity_items * 4).ok_or("vector allocation overflow")?;
                if allocation_end > 0x100000 { return Err("guest heap arena exhausted during singleton insertion".into()); }
                for index in 0..existing {
                    self.write32(ptr + index * 4, self.read32(begin + index * 4));
                }
                self.write32(ptr + existing * 4, self.read32(source));
                self.write32(ecx, ptr);
                self.write32(ecx + 4, ptr + length * 4);
                self.write32(ecx + 8, allocation_end);
                self.heap_next = (allocation_end + 15) & !15;
                Ok(0)
            }
            0x478d10 => {
                let position = self.read32(stack);
                let count = self.read32(stack + 4);
                let source = self.read32(stack + 8);
                let begin = self.read32(ecx);
                let end = self.read32(ecx + 4);
                let capacity = self.read32(ecx + 8);
                if ![0x131c2ac, 0x131c2c4].contains(&ecx)
                    || position != begin || count != 1 || begin != end || end != capacity
                {
                    return Err(format!("unexpected byte-vector insertion {ecx:#x}, {position:#x}, {count}, {source:#x}"));
                }
                let ptr = self.heap_next;
                let allocation_end = ptr.checked_add(1).ok_or("byte-vector allocation overflow")?;
                if allocation_end > 0x100000 { return Err("guest heap arena exhausted during byte-vector insertion".into()); }
                self.write8(ptr, self.read8(source));
                self.write32(ecx, ptr);
                self.write32(ecx + 4, ptr + 1);
                self.write32(ecx + 8, ptr + 1);
                self.heap_next = (allocation_end + 15) & !15;
                Ok(0)
            }
            0xf1abc0 => {
                let ptr = self.read32(stack);
                let needle = self.read32(stack + 4) as u8;
                let start = ptr as usize;
                let len = self.bytes[start..].iter().position(|byte| *byte == 0)
                    .ok_or("unterminated strrchr input")?;
                Ok(self.bytes[start..start + len].iter().rposition(|byte| *byte == needle)
                    .map(|offset| ptr + offset as u32).unwrap_or(0))
            }
            0xf18390 => {
                let destination = self.read32(stack);
                let value = self.read32(stack + 4) as u8;
                let count = self.read32(stack + 8) as usize;
                let start = destination as usize;
                self.bytes[start..start + count].fill(value);
                Ok(destination)
            }
            0x415b30 => {
                let source = self.read32(stack);
                let start = source as usize;
                let length = self.bytes[start..].iter().position(|byte| *byte == 0)
                    .ok_or("unterminated small string input")?;
                let destination = if length > 15 {
                    let ptr = self.heap_next;
                    let end = ptr.checked_add(length as u32 + 1).ok_or("small string allocation overflow")?;
                    if end > 0x100000 { return Err("guest heap arena exhausted during string allocation".into()); }
                    self.heap_next = (end + 15) & !15;
                    ptr
                } else {
                    ecx + 12
                };
                self.write32(ecx, destination);
                self.write32(ecx + 4, length as u32);
                self.write32(ecx + 8, if length > 15 { length as u32 } else { 15 });
                self.bytes.copy_within(start..start + length + 1, destination as usize);
                Ok(ecx)
            }
            0x4158d0 => {
                let requested = self.read32(stack);
                let current = self.read32(ecx);
                let length = self.read32(ecx + 4);
                let capacity = self.read32(ecx + 8);
                if requested <= capacity { return Ok(ecx); }
                let ptr = self.heap_next;
                let end = ptr.checked_add(requested + 1).ok_or("small string reserve overflow")?;
                if end > 0x100000 { return Err("guest heap arena exhausted during string reserve".into()); }
                self.bytes.copy_within(current as usize..current as usize + length as usize + 1, ptr as usize);
                self.write32(ecx, ptr);
                self.write32(ecx + 8, requested);
                self.heap_next = (end + 15) & !15;
                Ok(ecx)
            }
            0xf18440 => {
                let destination = self.read32(stack);
                let source = self.read32(stack + 4);
                let count = self.read32(stack + 8) as usize;
                self.bytes.copy_within(source as usize..source as usize + count, destination as usize);
                Ok(destination)
            }
            0x415ae0 => {
                let source = self.read32(stack);
                let source_ptr = self.read32(source);
                let length = self.read32(source + 4);
                let destination = if length > 15 {
                    let ptr = self.heap_next;
                    let end = ptr.checked_add(length + 1).ok_or("copied string allocation overflow")?;
                    if end > 0x100000 { return Err("guest heap arena exhausted during string copy".into()); }
                    self.heap_next = (end + 15) & !15;
                    ptr
                } else {
                    ecx + 12
                };
                self.write32(ecx, destination);
                self.write32(ecx + 4, length);
                self.write32(ecx + 8, if length > 15 { length } else { 15 });
                self.bytes.copy_within(source_ptr as usize..source_ptr as usize + length as usize + 1, destination as usize);
                Ok(ecx)
            }
            0x415e80 => {
                let destination_object = self.read32(stack);
                let source_object = self.read32(stack + 4);
                let suffix_ptr = self.read32(stack + 8);
                let source_ptr = self.read32(source_object);
                let source_len = self.read32(source_object + 4) as usize;
                let suffix_start = suffix_ptr as usize;
                let suffix_len = self.bytes[suffix_start..].iter().position(|byte| *byte == 0)
                    .ok_or("unterminated concatenation suffix")?;
                let length = source_len + suffix_len;
                let destination = if length > 15 {
                    let ptr = self.heap_next;
                    let end = ptr.checked_add(length as u32 + 1).ok_or("concatenated string allocation overflow")?;
                    if end > 0x100000 { return Err("guest heap arena exhausted during string concatenation".into()); }
                    self.heap_next = (end + 15) & !15;
                    ptr
                } else {
                    destination_object + 12
                };
                self.write32(destination_object, destination);
                self.write32(destination_object + 4, length as u32);
                self.write32(destination_object + 8, if length > 15 { length as u32 } else { 15 });
                self.bytes.copy_within(source_ptr as usize..source_ptr as usize + source_len, destination as usize);
                self.bytes.copy_within(suffix_start..suffix_start + suffix_len, destination as usize + source_len);
                self.write8(destination + length as u32, 0);
                Ok(destination_object)
            }
            0x415e10 => {
                let destination_object = self.read32(stack);
                let left_object = self.read32(stack + 4);
                let right_object = self.read32(stack + 8);
                let left_ptr = self.read32(left_object);
                let left_len = self.read32(left_object + 4) as usize;
                let right_ptr = self.read32(right_object);
                let right_len = self.read32(right_object + 4) as usize;
                let length = left_len + right_len;
                let destination = if length > 15 {
                    let ptr = self.heap_next;
                    let end = ptr.checked_add(length as u32 + 1).ok_or("combined string allocation overflow")?;
                    if end > 0x100000 { return Err("guest heap arena exhausted during string combination".into()); }
                    self.heap_next = (end + 15) & !15;
                    ptr
                } else {
                    destination_object + 12
                };
                self.write32(destination_object, destination);
                self.write32(destination_object + 4, length as u32);
                self.write32(destination_object + 8, if length > 15 { length as u32 } else { 15 });
                self.bytes.copy_within(left_ptr as usize..left_ptr as usize + left_len, destination as usize);
                self.bytes.copy_within(right_ptr as usize..right_ptr as usize + right_len, destination as usize + left_len);
                self.write8(destination + length as u32, 0);
                Ok(destination_object)
            }
            0x4137d0 => {
                if self.read32(stack) != 0x128cad0 {
                    return Err("unexpected game-free descriptor".into());
                }
                Ok(0)
            }
            0xf17ba1 => {
                if ecx != self.read32(COOKIE) {
                    return Err("security cookie mismatch".into());
                }
                Ok(ecx)
            }
            0x423280 => Ok(0x131a960),
            0x423730 => Ok(self.read32(stack)),
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
            0x421860 => {
                if self.read32(stack) != 0x12940b4 {
                    return Err("unexpected registry assertion descriptor".into());
                }
                Ok(0)
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
                let flags = self.read32(stack + 4);
                if self.read32(stack) != self.heap_result || ![0, 8].contains(&flags) {
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
                if flags & 8 != 0 {
                    self.bytes[ptr as usize..end as usize].fill(0);
                }
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
            0x10a7278 => Ok(0x18000),
            0x10a72e4 => Ok(if self.environment_variant == 1 { 0 } else { 0x18100 }),
            0x10a72c4 => {
                let args = (0..8).map(|n| self.read32(stack + 4 * n)).collect::<Vec<_>>();
                if args[0] != 0 || args[1] != 0 || args[2] != 0x18100
                    || args[3] != 13 || args[6] != 0 || args[7] != 0
                {
                    return Err(format!("unexpected WideCharToMultiByte arguments {args:?}"));
                }
                if self.environment_variant == 2 {
                    return Ok(0);
                }
                let converted = b"A=B\0LANG=ru\0\0";
                if args[4] != 0 {
                    if args[5] < converted.len() as u32 {
                        return Ok(0);
                    }
                    let start = args[4] as usize;
                    self.bytes[start..start + converted.len()].copy_from_slice(converted);
                }
                Ok(converted.len() as u32)
            }
            0x10a72e0 => {
                if self.read32(stack) != 0x18100 {
                    return Err("unexpected environment block token".into());
                }
                Ok(1)
            }
            0x10a72dc => {
                if self.read32(stack) != 0 || self.read32(stack + 4) != 0x1358b60
                    || self.read32(stack + 8) != 0x104
                {
                    return Err("unexpected GetModuleFileNameA arguments".into());
                }
                let name = b"Warframe.exe\0";
                self.bytes[0x1358b60..0x1358b60 + name.len()].copy_from_slice(name);
                Ok((name.len() - 1) as u32)
            }
            0xf25852 => {
                self.write32(0x1359dac, 1);
                Ok(0)
            }
            0xf30820 => Ok(0),
            0xf26890 => {
                let ptr = self.read32(stack) as usize;
                let length = self.bytes[ptr..].iter().position(|byte| *byte == 0)
                    .ok_or("unterminated strlen input")?;
                Ok(length as u32)
            }
            0xf28c15 => {
                let destination = self.read32(stack);
                let size = self.read32(stack + 4);
                let source = self.read32(stack + 8);
                if size == 0 {
                    return Ok(22);
                }
                let start = source as usize;
                let length = self.bytes[start..].iter().position(|byte| *byte == 0)
                    .ok_or("unterminated copy input")? + 1;
                if length > size as usize {
                    return Ok(34);
                }
                self.bytes.copy_within(start..start + length, destination as usize);
                Ok(0)
            }
            0xf1f0dc => Ok(0),
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
        environment_variant: 0,
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
    run_environment_checkpoints()?;
    run_argv_checkpoints()?;
    run_envp_checkpoints()?;
    run_cinit_checkpoints()?;
    run_preinitializer_checkpoints()?;
    run_atexit_checkpoints()?;
    run_constructor_checkpoints()?;
    run_constructor_two_checkpoints()?;
    run_constructor_three_checkpoints()?;
    run_constructor_four_checkpoints()?;
    run_constructor_eight_checkpoints()?;
    run_constructor_nine_checkpoints()?;
    run_constructor_twelve_checkpoints()?;
    run_constructor_twenty_two_checkpoints()?;
    run_constructor_twenty_four_checkpoints()?;
    run_constructor_twenty_five_checkpoints()?;
    run_constructor_thirty_two_checkpoints()?;
    run_constructor_thirty_three_checkpoints()?;
    run_constructor_thirty_seven_checkpoints()?;
    run_constructor_forty_one_checkpoints()?;
    run_constructor_forty_three_checkpoints()?;
    run_constructor_forty_four_checkpoints()?;
    run_constructor_forty_five_checkpoints()?;
    run_constructor_forty_six_checkpoints()?;
    run_constructor_forty_seven_checkpoints()?;
    run_constructor_forty_eight_checkpoints()?;
    run_constructor_forty_nine_checkpoints()?;
    run_constructor_fifty_checkpoints()?;
    run_constructor_fifty_one_checkpoints()?;
    run_constructor_fifty_two_checkpoints()?;
    run_constructor_fifty_three_checkpoints()?;
    run_constructor_fifty_five_checkpoints()?;
    run_constructor_fifty_six_checkpoints()?;
    run_constructor_fifty_seven_checkpoints()?;
    run_constructor_fifty_eight_checkpoints()?;
    run_constructor_fifty_nine_checkpoints()?;
    run_constructor_sixty_checkpoints()?;
    run_constructor_sixty_one_checkpoints()?;
    run_constructor_sixty_two_checkpoints()?;
    run_constructor_sixty_five_checkpoints()?;
    run_constructor_seventy_three_checkpoints()?;
    run_constructor_seventy_four_checkpoints()?;
    run_constructor_eighty_seven_checkpoints()?;
    run_constructor_ninety_one_checkpoints()?;
    run_constructor_ninety_two_checkpoints()?;
    run_constructor_one_hundred_two_checkpoints()?;
    run_constructor_one_hundred_ten_checkpoints()?;
    run_constructor_one_hundred_eleven_checkpoints()?;
    run_constructor_one_hundred_sixteen_checkpoints()?;
    run_constructor_one_hundred_seventeen_checkpoints()?;
    run_constructor_one_hundred_twenty_eight_checkpoints()?;
    run_constructor_one_hundred_twenty_nine_checkpoints()?;
    run_constructor_one_hundred_thirty_checkpoints()?;
    run_constructor_one_hundred_thirty_one_checkpoints()?;
    run_constructor_one_hundred_thirty_seven_checkpoints()?;
    run_constructor_one_hundred_forty_three_checkpoints()?;
    run_constructor_one_hundred_forty_four_checkpoints()?;
    run_constructor_one_hundred_forty_five_checkpoint()?;
    run_constructor_one_hundred_forty_six_checkpoint()?;
    run_constructor_one_hundred_forty_seven_checkpoint()?;
    run_constructor_one_hundred_forty_eight_checkpoint()?;
    run_constructor_one_hundred_fifty_checkpoints()?;
    run_constructor_one_hundred_fifty_four_checkpoint()?;
    run_constructor_one_hundred_fifty_six_checkpoint()?;
    run_constructor_one_hundred_sixty_four_checkpoint()?;
    run_constructor_one_hundred_sixty_eight_checkpoint()?;
    run_constructor_one_hundred_seventy_eight_checkpoint()?;
    run_constructor_one_hundred_eighty_five_checkpoint()?;
    run_constructor_one_hundred_eighty_seven_checkpoint()?;
    run_constructor_two_hundred_twenty_nine_checkpoint()?;
    run_constructor_two_hundred_thirty_three_checkpoint()?;
    run_constructor_two_hundred_sixty_seven_checkpoint()?;
    run_constructor_two_hundred_sixty_eight_checkpoint()?;
    run_constructor_two_hundred_eighty_four_checkpoint()?;
    run_constructor_three_hundred_five_checkpoint()?;
    run_constructor_three_hundred_twenty_one_checkpoint()?;
    run_constructor_three_hundred_twenty_six_checkpoint()?;
    run_constructor_three_hundred_thirty_six_checkpoint()?;
    run_constructor_three_hundred_forty_checkpoint()?;
    run_constructor_three_hundred_forty_five_checkpoint()?;
    run_constructor_three_hundred_fifty_four_checkpoint()?;
    run_constructor_three_hundred_eighty_eight_checkpoint()?;
    run_constructor_four_hundred_checkpoint()?;
    run_constructor_four_hundred_one_checkpoint()?;
    run_constructor_four_hundred_sixteen_checkpoint()?;
    run_constructor_four_hundred_fifty_four_checkpoint()?;
    run_constructor_four_hundred_fifty_five_checkpoint()?;
    run_constructor_batch_checkpoint(456, 0x106da00)?;
    run_constructor_batch_checkpoint(457, 0x106dad0)?;
    run_constructor_batch_checkpoint(458, 0x106daf0)?;
    run_constructor_batch_checkpoint(459, 0x106db40)?;
    run_constructor_batch_checkpoint(460, 0x106db60)?;
    run_constructor_batch_checkpoint(465, 0x106dcc0)?;
    run_constructor_batch_checkpoint(466, 0x106dd60)?;
    run_constructor_batch_checkpoint(471, 0x106de70)?;
    run_constructor_batch_checkpoint(473, 0x106df20)?;
    run_constructor_batch_checkpoint(476, 0x106e010)?;
    run_constructor_batch_checkpoint(478, 0x106e150)?;
    run_constructor_batch_checkpoint(479, 0x106e220)?;
    run_constructor_batch_checkpoint(480, 0x106e2f0)?;
    run_constructor_batch_checkpoint(483, 0x106e3e0)?;
    run_constructor_batch_checkpoint(487, 0x106e720)?;
    run_constructor_batch_checkpoint(491, 0x106ea00)?;
    run_constructor_batch_checkpoint(494, 0x106ea60)?;
    run_constructor_batch_checkpoint(500, 0x106ee20)?;
    run_constructor_batch_checkpoint(506, 0x106f300)?;
    run_constructor_batch_checkpoint(512, 0x106f7e0)?;
    run_constructor_batch_checkpoint(526, 0x106fe20)?;
    run_constructor_batch_checkpoint(555, 0x10703f0)?;
    run_constructor_batch_checkpoint(585, 0x1070d70)?;
    run_constructor_batch_checkpoint(625, 0x1071d00)?;
    run_constructor_batch_checkpoint(675, 0x1072a70)?;
    run_constructor_batch_checkpoint(688, 0x1073160)?;
    run_constructor_batch_checkpoint(690, 0x1073210)?;
    run_constructor_batch_checkpoint(724, 0x1073ad0)?;
    run_constructor_batch_checkpoint(725, 0x1073ba0)?;
    run_constructor_batch_checkpoint(736, 0x10742d0)?;
    run_constructor_batch_checkpoint(754, 0x10749e0)?;
    run_constructor_batch_checkpoint(778, 0x10752f0)?;
    run_constructor_batch_checkpoint(798, 0x1075ff0)?;
    run_constructor_batch_checkpoint(807, 0x1076220)?;
    run_constructor_batch_checkpoint(808, 0x1076240)?;
    run_constructor_batch_checkpoint(847, 0x1076680)?;
    run_constructor_batch_checkpoint(852, 0x10769d0)?;
    run_constructor_batch_checkpoint(854, 0x1076a70)?;
    run_constructor_batch_checkpoint(855, 0x1076b10)?;
    run_constructor_batch_checkpoint(864, 0x1076e40)?;
    run_constructor_batch_checkpoint(870, 0x10770a0)?;
    run_constructor_batch_checkpoint(880, 0x1077330)?;
    run_constructor_batch_checkpoint(897, 0x1077730)?;
    run_constructor_batch_checkpoint(916, 0x1077b10)?;
    run_constructor_batch_checkpoint(919, 0x1077d00)?;
    run_constructor_batch_checkpoint(928, 0x1078000)?;
    run_constructor_batch_checkpoint(933, 0x10783b0)?;
    run_constructor_batch_checkpoint(940, 0x1078720)?;
    run_constructor_batch_checkpoint(947, 0x10789f0)?;
    run_constructor_batch_checkpoint(952, 0x1078bd0)?;
    run_constructor_batch_checkpoint(959, 0x1079010)?;
    run_constructor_batch_checkpoint(968, 0x10791c0)?;
    run_constructor_batch_checkpoint(978, 0x1079450)?;
    run_constructor_batch_checkpoint(999, 0x1079ae0)?;
    run_constructor_batch_checkpoint(1009, 0x1079ce0)?;
    run_constructor_batch_checkpoint(1021, 0x1079ee0)?;
    run_constructor_batch_checkpoint(1072, 0x107a9a0)?;
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
        environment_variant: 0,
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
        0x10a70a8, 0x10a72ec, 0x10a72f0, 0x10a72f4, 0x10a7284, 0x10a7288,
        0x10a72f8, 0x10a72c4,
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
    let command = b"Warframe.exe -language:ru -fullscreen:0\0";
    m.bytes[0x18000..0x18000 + command.len()].copy_from_slice(command);
    for (index, word) in "A=B\0LANG=ru\0\0".encode_utf16().enumerate() {
        m.write16(0x18100 + index as u32 * 2, word as u32);
    }
    m
}

fn run_environment_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        m.environment_variant = variant;
        translated::run(&mut m, 0xf17c9d)?;
        let environment = m.read32(0x1358030);
        let data = if environment == 0 {
            String::new()
        } else {
            m.bytes[environment as usize..environment as usize + 13]
                .iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        println!("STARTUP_ENVIRONMENT_READY variant={variant:08x} stop=00f17c9d stack={:08x} frame={:08x} eax={:08x} command={:08x} environment={environment:08x} next={:08x} data={data} calls={}",
            m.stack, m.frame, m.eax, m.read32(0x1359db8), m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_argv_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0xf17cae)?;
    let argc = m.read32(0x135806c);
    let argv = m.read32(0x1358070);
    let pointers = (0..argc + 1)
        .map(|index| m.read32(argv + index * 4))
        .map(|value| format!("{value:08x}"))
        .collect::<Vec<_>>().join(",");
    let data = m.bytes[argv as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_ARGV_READY stop=00f17cae stack={:08x} frame={:08x} eax={:08x} argc={argc:08x} argv={argv:08x} next={:08x} pointers={pointers} data={data} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_envp_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0xf17cbf)?;
    let envp = m.read32(0x1358078);
    let pointers = (0..3).map(|index| m.read32(envp + index * 4))
        .map(|value| format!("{value:08x}"))
        .collect::<Vec<_>>().join(",");
    let data = m.bytes[envp as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_ENVP_READY stop=00f17cbf stack={:08x} frame={:08x} eax={:08x} envp={envp:08x} initialized={:08x} next={:08x} pointers={pointers} data={data} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x1359da0), m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_cinit_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0xf207b3)?;
    let pointers = (0..10)
        .map(|index| m.read32(0x1310ef8 + index * 4))
        .map(|value| format!("{value:08x}"))
        .collect::<Vec<_>>().join(",");
    println!("STARTUP_CINIT_POINTERS_READY stop=00f207b3 stack={:08x} frame={:08x} eax={:08x} pointers={pointers} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_preinitializer_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0xf207c4)?;
    let fields = [0x135ade0, 0x1359dc0, 0x1359da8, 0x1359da4,
                  0x1358040, 0x1358044, 0x1359c84, 0x1359c7c, 0x1359dac]
        .iter().map(|addr| m.read32(*addr))
        .map(|value| format!("{value:08x}"))
        .collect::<Vec<_>>().join(",");
    let table = m.read32(0x1359dc0);
    let count = m.read32(0x135ade0);
    let data = m.bytes[table as usize..table as usize + count as usize * 4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_PREINITIALIZERS_READY stop=00f207c4 stack={:08x} frame={:08x} eax={:08x} next={:08x} fields={fields} data={data} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_atexit_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0xf207d4)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let data = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_ATEXIT_READY stop=00f207d4 stack={:08x} frame={:08x} eax={:08x} begin={begin:08x} end={end:08x} encoded_begin={:08x} encoded_end={:08x} data={data} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x1359da8), m.read32(0x1359da4),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10670f0)?;
    println!("STARTUP_CONSTRUCTOR_001_READY stop=010670f0 stack={:08x} frame={:08x} eax={:08x} lhs={:08x} rhs={:08x} result={:08x} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x128b0fc), m.read32(0x10a9cc8),
        m.read32(0x1316330),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067120)?;
    let object = m.bytes[0x1316334..0x1316341]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_002_READY stop=01067120 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067150)?;
    let object = m.bytes[0x1316344..0x1316351]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_003_READY stop=01067150 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067180)?;
    let object = m.bytes[0x1316358..0x13163dc]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_004_READY stop=01067180 stack={:08x} frame={:08x} eax={:08x} pool={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131a9e0),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_eight_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067260)?;
    let objects = m.bytes[0x13163e0..0x13165d0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_008_READY stop=01067260 stack={:08x} frame={:08x} eax={:08x} objects={objects} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_nine_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067270)?;
    let object = m.bytes[0x13165d0..0x1316610]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_009_READY stop=01067270 stack={:08x} frame={:08x} eax={:08x} object={object} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_twelve_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10672e0)?;
    let objects = m.bytes[0x1316618..0x1316924]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_012_READY stop=010672e0 stack={:08x} frame={:08x} eax={:08x} objects={objects} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_twenty_two_checkpoints() -> Result<(), String> {
    for variant in 0..3 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant != 0 {
            // Force the pairwise string comparison to continue past one pair.
            m.write32(0x1316920, 0x70000);
            m.write32(0x70004, 0x70100);
            m.write32(0x70038, 0);
            let name = if variant == 1 { b"SysX\0".as_slice() } else { b"Sys\0".as_slice() };
            m.bytes[0x70100..0x70100 + name.len()].copy_from_slice(name);
        }
        translated::run(&mut m, 0x1067420)?;
        let objects = m.bytes[0x1316924..0x1316b8c]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_022_READY variant={variant} stop=01067420 stack={:08x} frame={:08x} eax={:08x} head={:08x} objects={objects} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.read32(0x1316920),
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_twenty_four_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067440)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_024_READY stop=01067440 stack={:08x} frame={:08x} eax={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_twenty_five_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067460)?;
    let object = m.bytes[0x1316bc0..0x1316d65]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_025_READY stop=01067460 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_thirty_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10674d0)?;
    let globals = m.bytes[0x1316d7c..0x1316d8c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_032_READY stop=010674d0 stack={:08x} frame={:08x} eax={:08x} globals={globals} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_thirty_three_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10674f0)?;
    println!("STARTUP_CONSTRUCTOR_033_READY stop=010674f0 stack={:08x} frame={:08x} eax={:08x} timer={:08x}{:08x} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x1317f3c), m.read32(0x1317f38),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_thirty_seven_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067560)?;
    let digest = m.bytes[0x131a024..0x131a07c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_037_READY stop=01067560 stack={:08x} frame={:08x} eax={:08x} digest={digest} scalar={:08x} pool={:08x} interned={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131a950), m.read32(0x131a9e0),
        m.read32(0x131a954),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_one_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067630)?;
    let objects = m.bytes[0x131a958..0x131ab28]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let scalars = m.bytes[0x128d594..0x128d59c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_041_READY stop=01067630 stack={:08x} frame={:08x} eax={:08x} objects={objects} scalars={scalars} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_three_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067650)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_043_READY stop=01067650 stack={:08x} frame={:08x} eax={:08x} counter={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x128d96c),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_four_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067670)?;
    let object = m.bytes[0x131ac80..0x131ac94]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_044_READY stop=01067670 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}


fn run_constructor_forty_five_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 {
            m.write32(0x131c364, 1);
            m.write32(0x131c360, 0x10ba030);
        }
        translated::run(&mut m, 0x10676a0)?;
        let object = m.bytes[0x131ac9c..0x131acb0]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_045_READY variant={variant} stop=010676a0 stack={:08x} frame={:08x} eax={:08x} source={:08x} object={object} calls={}",
            m.stack, m.frame, m.eax, m.read32(0x131c360),
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_forty_six_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067710)?;
    let object = m.bytes[0x80000..0x8001c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_046_READY stop=01067710 stack={:08x} frame={:08x} eax={:08x} pointer={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131acb0),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_seven_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067780)?;
    let object = m.bytes[0x131ad98..0x131ae20]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let shared = m.read32(0x131ad88);
    let manager = m.bytes[shared as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_047_READY stop=01067780 stack={:08x} frame={:08x} eax={:08x} shared={:08x} next={:08x} object={object} manager={manager} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, shared, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_eight_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067810)?;
    let object = m.bytes[0x131ae20..0x131aec0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let shared = m.read32(0x131ad88);
    let manager = m.bytes[shared as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_048_READY stop=01067810 stack={:08x} frame={:08x} eax={:08x} shared={shared:08x} next={:08x} object={object} manager={manager} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_forty_nine_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067880)?;
    let object = m.bytes[0x131aec0..0x131af48]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let shared = m.read32(0x131ad88);
    let manager = m.bytes[shared as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_049_READY stop=01067880 stack={:08x} frame={:08x} eax={:08x} shared={shared:08x} next={:08x} object={object} manager={manager} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067910)?;
    let object = m.bytes[0x131af48..0x131afe0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let shared = m.read32(0x131ad88);
    let manager = m.bytes[shared as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_050_READY stop=01067910 stack={:08x} frame={:08x} eax={:08x} shared={shared:08x} next={:08x} object={object} manager={manager} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_one_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067930)?;
    let vector = m.bytes[0x128eb94..0x128eba0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_051_READY stop=01067930 stack={:08x} frame={:08x} eax={:08x} next={:08x} vector={vector} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067950)?;
    let object = m.bytes[0x131aff8..0x131b194]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_052_READY stop=01067950 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_three_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067980)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_053_READY stop=01067980 stack={:08x} frame={:08x} eax={:08x} module={:08x} function={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131b1b8), m.read32(0x131b1bc),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_five_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10679a0)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_055_READY stop=010679a0 stack={:08x} frame={:08x} eax={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_six_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10679c0)?;
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_056_READY stop=010679c0 stack={:08x} frame={:08x} eax={:08x} object={:08x} counter={:08x} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131b1c8), m.read32(0x128d970),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_seven_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 {
            m.write8(0x131b234, 1);
            m.write32(0x131b1f0, 0x80000);
            m.write32(0x131b1f4, 0x80000);
            m.write32(0x131b1f8, 0x80004);
        }
        translated::run(&mut m, 0x1067a10)?;
        let singleton = m.bytes[0x131b1e0..0x131b230]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_057_READY variant={variant} stop=01067a10 stack={:08x} frame={:08x} eax={:08x} next={:08x} item={:08x} singleton={singleton} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next, m.read32(0x80000),
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_fifty_eight_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067a20)?;
    println!("STARTUP_CONSTRUCTOR_058_READY stop=01067a20 stack={:08x} frame={:08x} eax={:08x} value={:08x} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131b238),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_fifty_nine_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067a50)?;
    let object = m.bytes[0x131b23c..0x131b24c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_059_READY stop=01067a50 stack={:08x} frame={:08x} eax={:08x} object={object} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_sixty_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 {
            m.write8(0x131b234, 1);
            m.write32(0x131b1f0, 0x80000);
            m.write32(0x131b1f4, 0x80000);
            m.write32(0x131b1f8, 0x80008);
        }
        translated::run(&mut m, 0x1067aa0)?;
        let singleton = m.bytes[0x131b1e0..0x131b230]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let vector = m.read32(0x131b1f0);
        let items = m.bytes[vector as usize..m.read32(0x131b1f4) as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_060_READY variant={variant} stop=01067aa0 stack={:08x} frame={:08x} eax={:08x} next={:08x} object={:08x} singleton={singleton} items={items} calls={}",
            m.stack, m.frame, m.eax, m.heap_next, m.read32(0x128fbb0),
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_sixty_one_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067ad0)?;
    let object = m.bytes[0x131b24c..0x131b25c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_061_READY stop=01067ad0 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_sixty_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067b00)?;
    let object = m.bytes[0x131b25c..0x131b26c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_062_READY stop=01067b00 stack={:08x} frame={:08x} eax={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_sixty_five_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067ba0)?;
    let objects = m.bytes[0x131b26c..0x131b350]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_065_READY stop=01067ba0 stack={:08x} frame={:08x} eax={:08x} objects={objects} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_seventy_three_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067e00)?;
    let objects = m.bytes[0x131b358..0x131b808]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_073_READY stop=01067e00 stack={:08x} frame={:08x} eax={:08x} objects={objects} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_seventy_four_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1067e20)?;
    let object = m.bytes[0x131b808..0x131b878]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_074_READY stop=01067e20 stack={:08x} frame={:08x} eax={:08x} count_a={:08x} count_b={:08x} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x128d96c), m.read32(0x128d970),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_eighty_seven_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068060)?;
    let state = m.bytes[0x131b878..0x131be38]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let string_ptr = m.read32(0x131ba9c);
    let string = m.bytes[string_ptr as usize..string_ptr as usize + 24]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_087_READY stop=01068060 stack={:08x} frame={:08x} eax={:08x} next={:08x} counter={:08x} state={state} string={string} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next, m.read32(0x128d970),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_ninety_one_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10681a0)?;
    let state = m.bytes[0x131be38..0x131c198]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_091_READY stop=010681a0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_ninety_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10681c0)?;
    let object = m.bytes[0x131c198..0x131c2e4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let first = m.read32(0x131c2ac);
    let second = m.read32(0x131c2c4);
    let items = format!("{:02x}{:02x}", m.read8(first), m.read8(second));
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_092_READY stop=010681c0 stack={:08x} frame={:08x} eax={:08x} next={:08x} counter={:08x} object={object} items={items} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next, m.read32(0x128d970),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_two_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10682c0)?;
    let state = m.bytes[0x131c2e4..0x131c4d4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let string_ptr = m.read32(0x131c4a8);
    let string_len = m.read32(0x131c4ac);
    let string = m.bytes[string_ptr as usize..string_ptr as usize + string_len as usize + 1]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_102_READY stop=010682c0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} string={string} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_ten_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068420)?;
    let state = m.bytes[0x131c4d4..0x131c560]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let globals = m.bytes[0x1293e24..0x1293e34]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let object_ptr = m.read32(0x131c524);
    let object = m.bytes[object_ptr as usize..object_ptr as usize + 24]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_110_READY stop=01068420 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} globals={globals} object={object} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_eleven_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10684d0)?;
    let state = m.bytes[0x131c55c..0x131c574]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let string_ptr = m.read32(0x131c564);
    let string_len = m.read32(0x131c568);
    let string = m.bytes[string_ptr as usize..string_ptr as usize + string_len as usize + 1]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_111_READY stop=010684d0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} string={string} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_sixteen_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068620)?;
    let state = m.bytes[0x131c7c8..0x131ca94]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_116_READY stop=01068620 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_seventeen_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068640)?;
    let object = m.bytes[0x131ca94..0x131cad0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let tail_start = m.heap_next.saturating_sub(128).max(0x80000);
    let heap_tail = m.bytes[tail_start as usize..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_117_READY stop=01068640 stack={:08x} frame={:08x} eax={:08x} next={:08x} tail_start={tail_start:08x} object={object} heap_tail={heap_tail} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_twenty_eight_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068900)?;
    let state = m.bytes[0x131cad0..0x131cfd8]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_128_READY stop=01068900 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_twenty_nine_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x10689a0)?;
    let object = m.bytes[0x131cfd8..0x131cff0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let string_ptr = m.read32(0x131cfe0);
    let string_len = m.read32(0x131cfe4);
    let string = m.bytes[string_ptr as usize..string_ptr as usize + string_len as usize + 1]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_129_READY stop=010689a0 stack={:08x} frame={:08x} eax={:08x} next={:08x} object={object} string={string} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_thirty_checkpoints() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.heap_result = 0x60000;
    translated::run(&mut m, 0x1068a40)?;
    let object = m.bytes[0x131cffc..0x131d014]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let string_ptr = m.read32(0x131d004);
    let string_len = m.read32(0x131d008);
    let string = m.bytes[string_ptr as usize..string_ptr as usize + string_len as usize + 1]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_130_READY stop=01068a40 stack={:08x} frame={:08x} eax={:08x} next={:08x} object={object} string={string} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_thirty_one_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 { m.allocation_fail_at = 0; }
        translated::run(&mut m, 0x1068b10)?;
        let object = m.bytes[0x131d020..0x131d048]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let callback_ptr = m.read32(0x131d044);
        let callback = m.bytes[callback_ptr as usize..callback_ptr as usize + 8]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_131_READY variant={variant} stop=01068b10 stack={:08x} frame={:08x} eax={:08x} next={:08x} object={object} callback={callback} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_one_hundred_thirty_seven_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 { m.allocation_fail_at = 0; }
        translated::run(&mut m, 0x1068ef0)?;
        let state = m.bytes[0x131d048..0x131d230]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_137_READY variant={variant} stop=01068ef0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_one_hundred_forty_three_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 { m.allocation_fail_at = 0; }
        translated::run(&mut m, 0x10691b0)?;
        let state = m.bytes[0x131d17c..0x131d5c8]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_143_READY variant={variant} stop=010691b0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_one_hundred_forty_four_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 { m.allocation_fail_at = 0; }
        translated::run(&mut m, 0x1069280)?;
        let state = m.bytes[0x131d17c..0x131d5f0]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_144_READY variant={variant} stop=01069280 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_one_hundred_forty_five_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x10692a0)?;
    let state = m.bytes[0x131d5f0..0x131d5f9]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_145_READY stop=010692a0 stack={:08x} frame={:08x} eax={:08x} state={state} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_forty_six_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x10692c0)?;
    let state = m.bytes[0x131d5f0..0x131d614]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_146_READY stop=010692c0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_forty_seven_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x10692e0)?;
    let state = m.bytes[0x131d5f0..0x131d618]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_147_READY stop=010692e0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_forty_eight_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069300)?;
    println!("STARTUP_CONSTRUCTOR_148_READY stop=01069300 stack={:08x} frame={:08x} eax={:08x} value={:08x} calls={}",
        m.stack, m.frame, m.eax, m.read32(0x131d6e0),
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_fifty_checkpoints() -> Result<(), String> {
    for variant in 0..2 {
        let mut m = seh_memory(0, 0xffffffff);
        m.heap_result = 0x60000;
        if variant == 1 { m.allocation_fail_at = 0; }
        m.write32(0x1317f10, 1);
        m.write32(0x1317f18, 42);
        translated::run(&mut m, 0x10694a0)?;
        let state = m.bytes[0x131d5f0..0x131d734]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
        let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
        let callbacks = m.bytes[begin as usize..end as usize]
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        println!("STARTUP_CONSTRUCTOR_150_READY variant={variant} stop=010694a0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} callbacks={callbacks} calls={}",
            m.stack, m.frame, m.eax, m.heap_next,
            m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    }
    Ok(())
}

fn run_constructor_one_hundred_fifty_four_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x10695e0)?;
    let state = m.bytes[0x131d738..0x131d998]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_154_READY stop=010695e0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_fifty_six_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069720)?;
    let state = m.bytes[0x131d99c..0x131d9e4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_156_READY stop=01069720 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_sixty_four_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x10699a0)?;
    let state = m.bytes[0x131d9e8..0x131ded8]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_164_READY stop=010699a0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_sixty_eight_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069b30)?;
    let state = m.bytes[0x131def8..0x131e0d8]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_168_READY stop=01069b30 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_seventy_eight_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069dc0)?;
    let state = m.bytes[0x131e400..0x131e978]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_178_READY stop=01069dc0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_eighty_five_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069e80)?;
    let state = m.bytes[0x131e978..0x131ed28]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_185_READY stop=01069e80 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_one_hundred_eighty_seven_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x1069f20)?;
    let state = m.bytes[0x131ed28..0x131ee50]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_187_READY stop=01069f20 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_hundred_twenty_nine_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106a1c0)?;
    let state = m.bytes[0x131ed24..0x131eef4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_229_READY stop=0106a1c0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_hundred_thirty_three_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106a210)?;
    let state = m.bytes[0x131ed24..0x131f09c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_233_READY stop=0106a210 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_hundred_sixty_seven_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106abb0)?;
    let state = m.bytes[0x131f0a0..0x13220b8]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_267_READY stop=0106abb0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_hundred_sixty_eight_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106abf0)?;
    let state = m.bytes[0x13220c8..0x13220f4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let registry = (0..3).map(|index| m.read32(0x131c580 + index * 4))
        .map(|value| format!("{value:08x}")).collect::<Vec<_>>().join(",");
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_268_READY stop=0106abf0 stack={:08x} frame={:08x} eax={:08x} next={:08x} registry={registry} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_two_hundred_eighty_four_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106aff0)?;
    let state = m.bytes[0x13220c8..0x13223d4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let registry_object = m.read32(0x131c580);
    let registry = (0..3).map(|index| m.read32(registry_object + index * 4))
        .map(|value| format!("{value:08x}")).collect::<Vec<_>>().join(",");
    let registry_data = m.bytes[m.read32(registry_object) as usize..m.read32(registry_object + 4) as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_284_READY stop=0106aff0 stack={:08x} frame={:08x} eax={:08x} next={:08x} registry_object={registry_object:08x} registry={registry} registry_data={registry_data} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_five_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106b550)?;
    let state = m.bytes[0x13223d8..0x1322e58]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_305_READY stop=0106b550 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_twenty_one_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106b900)?;
    let state = m.bytes[0x1322e5c..0x132371c]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_321_READY stop=0106b900 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_twenty_six_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106b9f0)?;
    let state = m.bytes[0x129ff7c..0x12a0020]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_326_READY stop=0106b9f0 stack={:08x} frame={:08x} eax={:08x} state={state} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_thirty_six_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106bcf0)?;
    let state = m.bytes[0x1323720..0x1323db0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_336_READY stop=0106bcf0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_forty_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106bdb0)?;
    let state = m.bytes[0x1324028..0x13240c0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_340_READY stop=0106bdb0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_forty_five_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106bee0)?;
    let state = m.bytes[0x13240c0..0x13242a0]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_345_READY stop=0106bee0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_fifty_four_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106c1b0)?;
    let state = m.bytes[0x13242b0..0x1324a00]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_354_READY stop=0106c1b0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_three_hundred_eighty_eight_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106c9a0)?;
    let state = m.bytes[0x1324ac0..0x1326000]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_388_READY stop=0106c9a0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_hundred_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106cce0)?;
    let state = m.bytes[0x1326000..0x1327000]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_400_READY stop=0106cce0 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_hundred_one_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106cd50)?;
    let state = m.bytes[0x12a7794..0x12a77a4]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_401_READY stop=0106cd50 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_hundred_sixteen_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106cf50)?;
    let state = m.bytes[0x128d970..0x128da00].iter()
        .chain(m.bytes[0x1327000..0x1328000].iter())
        .map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_416_READY stop=0106cf50 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_hundred_fifty_four_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106d860)?;
    let state = m.bytes[0x1326080..0x1328000]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_454_READY stop=0106d860 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}

fn run_constructor_four_hundred_fifty_five_checkpoint() -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, 0x106d930)?;
    let state = m.bytes[0x1328000..0x1329000]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_455_READY stop=0106d930 stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
}







fn run_constructor_batch_checkpoint(number: u32, stop: u32) -> Result<(), String> {
    let mut m = seh_memory(0, 0xffffffff);
    m.write32(0x1317f10, 1);
    m.write32(0x1317f18, 42);
    translated::run(&mut m, stop)?;
    let state = m.bytes[0x1327000..0x1328000]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let heap = m.bytes[0x80000..m.heap_next as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let begin = m.read32(0x1359da8) ^ STARTUP_FIXTURE_POINTER_XOR;
    let end = m.read32(0x1359da4) ^ STARTUP_FIXTURE_POINTER_XOR;
    let callbacks = m.bytes[begin as usize..end as usize]
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("STARTUP_CONSTRUCTOR_{number:03}_READY stop={stop:08x} stack={:08x} frame={:08x} eax={:08x} next={:08x} state={state} heap={heap} callbacks={callbacks} calls={}",
        m.stack, m.frame, m.eax, m.heap_next,
        m.calls.iter().map(|slot| format!("{slot:08x}")).collect::<Vec<_>>().join(","));
    Ok(())
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
