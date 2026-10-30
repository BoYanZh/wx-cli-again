/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
///
/// 取钥路径（按微信版本从新到旧）：
/// 1. 微信 4.1.x：只读遍历运行时 `com.Tencent.WCDB.Config.Cipher` 配置对象，
///    读出 XOR 掩码保护的 blob 再抓 `x'<key>'` 字面量（见 `scan_config_cipher`）
/// 2. `x'<key><salt>'` 明文缓存（4.0.x 一代）
/// 3. salt 邻接的 32 字节 raw key（兜底：新版堆上仍可能出现 key||salt）
///
/// 三条路径的候选最后统一用 `match_key_hexes`（SQLCipher4 page1 HMAC）逐库验证。
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_key_hex, decode_salt_hex,
    is_writable_readable_page, match_key_hexes, scan_key_patterns, unique_key_hexes, KeyEntry,
    MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────
// 微信 4.1.x：运行时 WCDB `Config.Cipher` 扫描常量
//
// 移植自 TANGandXUE/wcdb-key-tool `wcdb_key_tool_windows.py`
// (`_scan_windows_v411_config_cipher` / `_windows_v411_config_key_candidates`)。
// 微信 4.1+ 不再把 `x'<key><salt>'` 明文留在内存里，真正的 per-DB key 缓存在
// WCDB 的 Config.Cipher 配置字符串中（XOR 掩码保护），必须沿
// "配置项名 → string 对象 → Config 对象 → blob" 这条链读出来。
//
// 下面所有偏移/掩码都在微信 4.1.11 / 4.1.15 上实测；版本再变就只能靠日志里
// 的 needle/node 计数判断是否漂移（未知版本只告警，不阻断兜底扫描）。
// ─────────────────────────────────────────────────────────────────────────

/// WCDB 配置项名（WeChat 4.1.x）。
const CONFIG_CIPHER_NEEDLE: &[u8] = b"com.Tencent.WCDB.Config.Cipher";

/// `Config.Cipher` 值在内存中的 32 字节循环 XOR 掩码（微信 4.1.x 实测）。
/// 来源：`wcdb_key_tool_windows.py::WINDOWS_CONFIG_XOR_MASK`
/// = `d2c7442458020000004889442450488b450048844c2448488944254048584c24`
const CONFIG_CIPHER_XOR_MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];

/// blob（XOR 前的密文）长度上限：正常配置串约 99 字节，1024 是安全上限。
const CONFIG_CIPHER_BLOB_MAX: u64 = 1024;

/// 正常 `Config.Cipher` blob 的长度（只用于统计诊断）。
const CONFIG_CIPHER_TYPICAL_BLOB_LEN: usize = 99;

/// 合法用户态地址区间（与 python 版 `0x10000 <= ptr < 0x800000000000` 一致）。
const MIN_USER_ADDRESS: usize = 0x0001_0000;
const MAX_USER_ADDRESS: usize = 0x0000_8000_0000_0000;

/// 引用对 `(needle 地址, needle 长度)` 命中位置往前 0x10 就是 string 对象的 node。
const CONFIG_STRING_REF_BACKTRACK: usize = 0x10;
/// node 需要读取的字节数 / 最小可用长度。
const CONFIG_NODE_READ_LEN: usize = 0x50;
const CONFIG_NODE_MIN_LEN: usize = 0x40;
/// node+0x10 → 内容指针（必须指回 needle），node+0x18 → 长度。
const CONFIG_NODE_DATA_PTR_OFF: usize = 0x10;
const CONFIG_NODE_LEN_OFF: usize = 0x18;
/// node+0x28 → 拥有该配置项的 Config 对象指针。
const CONFIG_NODE_OWNER_PTR_OFF: usize = 0x28;
/// Config 对象里 Cipher 字段的位置与其 `{len, ptr}` 布局。
const CONFIG_CIPHER_FIELD_OFF: usize = 0x88;
const CONFIG_CIPHER_FIELD_READ_LEN: usize = 0x28;
const CONFIG_CIPHER_FIELD_MIN_LEN: usize = 0x18;
/// 字段里 +0x8 → blob 指针，+0x10 → blob 长度。
const CONFIG_CIPHER_BLOB_PTR_OFF: usize = 0x8;
const CONFIG_CIPHER_BLOB_LEN_OFF: usize = 0x10;
/// 扫描引用对时的区块重叠（python 版用 0x80）。
const CONFIG_REF_OVERLAP: usize = 0x80;

/// 查找全部 Weixin.exe 进程 PID（按已提交内存从大到小）
///
/// 微信 4.x 常驻多个同名进程（主进程 + 若干几百 MB 的 helper）。快照返回顺序不定，
/// 只扫第一个可能错过真正持有 DB 密钥的进程，因此全部扫描、候选合并后再匹配。
fn find_wechat_pids() -> Vec<u32> {
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let Some(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok() }) else {
        return Vec::new();
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut candidates: Vec<u32> = Vec::new();
    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return Vec::new();
        }
        loop {
            let name =
                std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
            if name.eq_ignore_ascii_case("Weixin.exe") {
                candidates.push(entry.th32ProcessID);
            }
            if Process32Next(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
    if candidates.len() == 1 {
        return candidates;
    }

    // 多个同名进程：按已提交内存从大到小排（主进程通常最大），全部都扫
    let mut sized: Vec<(u32, usize)> = Vec::new();
    for pid in candidates {
        // SAFETY: 仅 QUERY_INFORMATION + 区域枚举，不读内容；打不开就跳过该候选
        let Some(proc) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok() }) else {
            continue;
        };
        let committed = committed_bytes(proc);
        unsafe {
            let _ = CloseHandle(proc);
        };
        eprintln!("Weixin.exe 候选 PID {}（已提交 {:.1} MB）", pid, committed as f64 / (1024.0 * 1024.0));
        sized.push((pid, committed));
    }
    sized.sort_by(|a, b| b.1.cmp(&a.1));
    sized.into_iter().map(|(pid, _)| pid).collect()
}

/// 统计进程已提交内存总量（仅枚举区域，不读内容；失败返回 0）
fn committed_bytes(process: HANDLE) -> usize {
    let mut total = 0usize;
    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }
        if mbi.State == MEM_COMMIT {
            total = total.saturating_add(mbi.RegionSize);
        }
        addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
        if addr == 0 {
            break; // overflow
        }
    }
    total
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pids = find_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 Weixin.exe 进程，请确认微信正在运行");
    }

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());

    // salt 原始字节：用于定位内存中与 salt 邻接的二进制 key。
    // 新版微信未必再保留 x'<key><salt>' 明文字符串，仅靠字符串模式会 0 候选；
    // salt 邻接是 macOS 同款兜底（见 macos.rs Phase 1），Windows 此前没接线。
    let salt_bytes: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(s, _)| decode_salt_hex(s))
        .collect();

    // 逐个扫描全部 Weixin.exe 进程并合并候选：DB 密钥可能不在主进程里
    let mut raw_keys: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    let mut seen_extra = HashSet::new();
    // 4.1.x Config.Cipher 候选：(key_hex, blob 里随附的 salt)
    let mut config_candidates: Vec<(String, Option<String>)> = Vec::new();
    let mut seen_config: HashSet<(String, Option<String>)> = HashSet::new();
    let mut stats = ConfigCipherStats::default();

    for pid in &pids {
        // SAFETY: OpenProcess 请求读取权限
        let process = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, *pid)
                .with_context(|| format!("OpenProcess 失败（PID {}），请以管理员权限运行", pid))?
        };
        let regions = collect_readable_regions(process);
        eprintln!(
            "扫描 PID {} 进程内存（{} 个可读区：x'hex' + salt 邻接 + WCDB Config.Cipher）...",
            pid,
            regions.len()
        );

        for &(base, size) in &regions {
            scan_region(
                process,
                base,
                size,
                &salt_bytes,
                &mut raw_keys,
                &mut extra_keys,
                &mut seen_extra,
            );
        }

        let mut pid_stats = ConfigCipherStats::default();
        scan_config_cipher(
            process,
            &regions,
            &mut config_candidates,
            &mut seen_config,
            &mut pid_stats,
        );
        eprintln!(
            "  PID {} Config.Cipher: needle {} 处 / string 引用 {} / node {} / config 指针 {} / blob {}（{}B 的 {} 个）/ 候选 key {}",
            pid,
            pid_stats.needle_occurrences,
            pid_stats.string_object_refs,
            pid_stats.node_candidates,
            pid_stats.config_ptr_candidates,
            pid_stats.blobs,
            CONFIG_CIPHER_TYPICAL_BLOB_LEN,
            pid_stats.blob99,
            pid_stats.candidates
        );
        stats += pid_stats;

        // SAFETY: 关闭进程句柄
        unsafe {
            let _ = CloseHandle(process);
        };
    }

    if stats.needle_occurrences == 0 {
        // 版本漂移只告警：未知版本仍可指望 x'hex'/salt 邻接兜底
        eprintln!(
            "[wx] 警告：微信进程内存里没有 {} 标记。\
             4.1.x 的结构体偏移可能随版本变化（本实现按 4.1.11 / 4.1.15 实测），\
             本次仅使用 x'hex'/salt 邻接兜底扫描。",
            String::from_utf8_lossy(CONFIG_CIPHER_NEEDLE)
        );
    }

    // Config.Cipher 候选并入匹配池：带 salt 的走 salt 优先，其余全局试
    for (key_hex, embedded_salt) in config_candidates.iter() {
        match embedded_salt {
            Some(salt) => {
                if !raw_keys.iter().any(|(k, s)| k == key_hex && s == salt) {
                    raw_keys.push((key_hex.clone(), salt.clone()));
                }
            }
            None => {
                if seen_extra.insert(key_hex.clone()) {
                    extra_keys.push(key_hex.clone());
                }
            }
        }
    }

    eprintln!(
        "共找到 {} 个 x'hex'/Config 候选，{} 个 salt 邻接候选（{} 个进程；Config.Cipher 候选 {} 个）",
        raw_keys.len(),
        extra_keys.len(),
        pids.len(),
        config_candidates.len()
    );

    // 合并候选：纯 key 候选（无 salt 配对）逐个试全部 DB
    let mut all_key_hexes = unique_key_hexes(&raw_keys);
    for k in &extra_keys {
        if !all_key_hexes.iter().any(|x| x == k) {
            all_key_hexes.push(k.clone());
        }
    }
    let entries = match_key_hexes(db_dir, &all_key_hexes, &raw_keys, &db_salts);
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（来自 {} 个候选 key）",
        entries.len(),
        db_salts.len(),
        all_key_hexes.len()
    );
    Ok(entries)
}

// ─────────────────────────────────────────────────────────────────────────
// 内存区枚举 / 分块读取
// ─────────────────────────────────────────────────────────────────────────

/// 只读可读页：密钥材料也可能落在只读映射 / 被冻结的缓冲里。
/// 写页判断走 `super::is_writable_readable_page`；这里只补两种非写可读保护。
fn is_readonly_readable_page(protect: u32) -> bool {
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_GUARD: u32 = 0x100;
    const PAGE_NOCACHE: u32 = 0x200;
    const PAGE_WRITECOMBINE: u32 = 0x400;
    // 去掉修饰位后比 base（与 mod.rs 的写法一致）
    let base = protect & !(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    base == PAGE_READONLY || base == PAGE_EXECUTE_READ
}

/// 该内存区是否值得扫描（已提交 + 可读）。
///
/// 与旧版一致：可写页（含 WRITECOPY / EXECUTE_*WRITE*，见
/// `is_writable_readable_page`，从 old-main #54 捞回）+ 只读页。新版微信的
/// x'<key><salt>' 字符串已消失，密钥材料可能落在只读映射里。
fn is_scan_readable_page(protect: u32) -> bool {
    is_writable_readable_page(protect) || is_readonly_readable_page(protect)
}

/// 枚举已提交且可读的内存区（基址, 大小）。
fn collect_readable_regions(process: HANDLE) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;
        if mbi.State == MEM_COMMIT && region_size > 0 && is_scan_readable_page(mbi.Protect.0) {
            regions.push((base, region_size));
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }

    regions
}

/// 读一段进程内存；读不到/读到 0 字节返回 None。
fn read_mem(process: HANDLE, addr: usize, size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let mut bytes_read: usize = 0;
    // SAFETY: ReadProcessMemory 读取目标进程内存，缓冲区长度与请求长度一致
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
        .is_ok()
    };
    if !ok || bytes_read == 0 {
        return None;
    }
    buf.truncate(bytes_read);
    Some(buf)
}

/// 从缓冲区小端读 u64（越界返回 None）。
fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    if end > buf.len() {
        return None;
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[offset..end]);
    Some(u64::from_le_bytes(raw))
}

/// 指针值 → 合法用户态地址。
fn addr_from_u64(value: u64) -> Option<usize> {
    let addr = usize::try_from(value).ok()?;
    (MIN_USER_ADDRESS..MAX_USER_ADDRESS)
        .contains(&addr)
        .then_some(addr)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 按块遍历一个内存区，块之间保留 `overlap` 字节（跨块的 needle/指针对不会漏）。
///
/// `visit(数据在目标进程中的地址, 数据)`。
fn scan_region_chunks(
    process: HANDLE,
    base: usize,
    size: usize,
    overlap: usize,
    mut visit: impl FnMut(usize, &[u8]),
) {
    let mut offset = 0usize;
    let mut tail: Vec<u8> = Vec::new();
    let mut tail_base = base;

    while offset < size {
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let chunk = read_mem(process, base + offset, chunk_size).unwrap_or_default();

        let data_base = if tail.is_empty() {
            base + offset
        } else {
            tail_base
        };
        let mut data = Vec::with_capacity(tail.len() + chunk.len());
        data.extend_from_slice(&tail);
        data.extend_from_slice(&chunk);

        if data.is_empty() {
            tail.clear();
            tail_base = base + offset + chunk_size;
        } else {
            visit(data_base, &data);
            if overlap > 0 {
                let keep = std::cmp::min(overlap, data.len());
                tail_base = data_base + data.len() - keep;
                tail = data[data.len() - keep..].to_vec();
            } else {
                tail.clear();
                tail_base = base + offset + chunk_size;
            }
        }

        offset += chunk_size;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 旧路径：x'<key><salt>' 明文 / salt 邻接
// ─────────────────────────────────────────────────────────────────────────

fn scan_region(
    process: HANDLE,
    base: usize,
    size: usize,
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    let overlap = MAX_PATTERN_BYTES;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            search_pattern(&buf, salts, raw_keys, extra_keys, seen_extra);
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

fn search_pattern(
    buf: &[u8],
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    scan_key_patterns(buf, raw_keys);
    collect_salt_adjacent_keys(buf, salts, extra_keys, seen_extra);
}

// ─────────────────────────────────────────────────────────────────────────
// 微信 4.1.x：Config.Cipher 扫描
// ─────────────────────────────────────────────────────────────────────────

/// Config.Cipher 扫描的计数（只用于诊断版本漂移，不影响取钥逻辑）。
#[derive(Debug, Clone, Copy, Default)]
struct ConfigCipherStats {
    /// needle（配置项名字符串）出现次数
    needle_occurrences: usize,
    /// (地址, 长度) 引用对命中次数
    string_object_refs: usize,
    /// 通过 node 校验的次数
    node_candidates: usize,
    /// 去重后的 Config 对象指针数
    config_ptr_candidates: usize,
    /// 成功读到 Cipher blob 的次数
    blobs: usize,
    /// 其中长度恰为 99 字节的 blob 数（正常配置串长度）
    blob99: usize,
    /// 去重后新增的候选 key 数
    candidates: usize,
}

impl std::ops::AddAssign for ConfigCipherStats {
    fn add_assign(&mut self, rhs: Self) {
        self.needle_occurrences += rhs.needle_occurrences;
        self.string_object_refs += rhs.string_object_refs;
        self.node_candidates += rhs.node_candidates;
        self.config_ptr_candidates += rhs.config_ptr_candidates;
        self.blobs += rhs.blobs;
        self.blob99 += rhs.blob99;
        self.candidates += rhs.candidates;
    }
}

fn scan_config_cipher(
    process: HANDLE,
    regions: &[(usize, usize)],
    candidates: &mut Vec<(String, Option<String>)>,
    seen_candidates: &mut HashSet<(String, Option<String>)>,
    stats: &mut ConfigCipherStats,
) {
    // 阶段 1：在已提交内存里找 needle（配置项名字符串本身）
    let mut needle_addrs: HashSet<usize> = HashSet::new();
    for &(base, size) in regions {
        scan_region_chunks(
            process,
            base,
            size,
            CONFIG_CIPHER_NEEDLE.len() - 1,
            |data_base, data| {
                let mut from = 0usize;
                while let Some(rel) = find_subslice(&data[from..], CONFIG_CIPHER_NEEDLE) {
                    needle_addrs.insert(data_base + from + rel);
                    from += rel + 1;
                }
            },
        );
    }
    stats.needle_occurrences += needle_addrs.len();
    if needle_addrs.is_empty() {
        return;
    }

    // 阶段 2：WCDB string 对象以 (内容地址, 长度) 两个 u64 存在内存里
    let patterns: Vec<[u8; 16]> = needle_addrs
        .iter()
        .map(|addr| {
            let mut pattern = [0u8; 16];
            pattern[..8].copy_from_slice(&(*addr as u64).to_le_bytes());
            pattern[8..].copy_from_slice(&(CONFIG_CIPHER_NEEDLE.len() as u64).to_le_bytes());
            pattern
        })
        .collect();

    let mut config_ptrs: HashSet<usize> = HashSet::new();

    // 阶段 3：引用对 → node → Config 对象 → Cipher blob → 候选 key
    for &(base, size) in regions {
        scan_region_chunks(process, base, size, CONFIG_REF_OVERLAP, |data_base, data| {
            for pattern in &patterns {
                let mut from = 0usize;
                while let Some(rel) = find_subslice(&data[from..], pattern) {
                    let pos = from + rel;
                    // 先推进游标，后面所有 continue 都不会重复命中同一处
                    from = pos + 1;
                    stats.string_object_refs += 1;

                    let Some(node_base) = (data_base + pos).checked_sub(CONFIG_STRING_REF_BACKTRACK)
                    else {
                        continue;
                    };
                    let Some(node) = read_mem(process, node_base, CONFIG_NODE_READ_LEN) else {
                        continue;
                    };
                    if node.len() < CONFIG_NODE_MIN_LEN {
                        continue;
                    }
                    // node+0x10 必须指回 needle，node+0x18 必须是 needle 长度
                    let Some(back_ptr) =
                        read_u64(&node, CONFIG_NODE_DATA_PTR_OFF).and_then(addr_from_u64)
                    else {
                        continue;
                    };
                    if !needle_addrs.contains(&back_ptr)
                        || read_u64(&node, CONFIG_NODE_LEN_OFF)
                            != Some(CONFIG_CIPHER_NEEDLE.len() as u64)
                    {
                        continue;
                    }
                    // node+0x28 → 拥有该配置项的 Config 对象
                    let Some(config_ptr) =
                        read_u64(&node, CONFIG_NODE_OWNER_PTR_OFF).and_then(addr_from_u64)
                    else {
                        continue;
                    };
                    stats.node_candidates += 1;
                    config_ptrs.insert(config_ptr);

                    // Config+0x88 → {len, ptr} 形态的 Cipher 值
                    let Some(field) = read_mem(
                        process,
                        config_ptr + CONFIG_CIPHER_FIELD_OFF,
                        CONFIG_CIPHER_FIELD_READ_LEN,
                    ) else {
                        continue;
                    };
                    if field.len() < CONFIG_CIPHER_FIELD_MIN_LEN {
                        continue;
                    }
                    let Some(blob_ptr) =
                        read_u64(&field, CONFIG_CIPHER_BLOB_PTR_OFF).and_then(addr_from_u64)
                    else {
                        continue;
                    };
                    let Some(blob_len) = read_u64(&field, CONFIG_CIPHER_BLOB_LEN_OFF) else {
                        continue;
                    };
                    if blob_len == 0 || blob_len > CONFIG_CIPHER_BLOB_MAX {
                        continue;
                    }
                    let Ok(blob_len) = usize::try_from(blob_len) else {
                        continue;
                    };
                    let Some(blob) = read_mem(process, blob_ptr, blob_len) else {
                        continue;
                    };
                    // 必须完整读到，否则 XOR 解码会错位
                    if blob.len() != blob_len {
                        continue;
                    }

                    stats.blobs += 1;
                    if blob_len == CONFIG_CIPHER_TYPICAL_BLOB_LEN {
                        stats.blob99 += 1;
                    }
                    for candidate in config_blob_candidates(&blob) {
                        if seen_candidates.insert(candidate.clone()) {
                            stats.candidates += 1;
                            candidates.push(candidate);
                        }
                    }
                }
            }
        });
    }

    stats.config_ptr_candidates += config_ptrs.len();
}

/// `x'<64~192 hex>'` 字面量（大小写 x 都认，与 python 版正则一致）。
fn config_literal_regex() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"[xX]'([0-9A-Fa-f]{64,192})'")
            .expect("内置 Config.Cipher 正则必须合法")
    })
}

/// XOR 解码 blob 后抓候选 key（及紧随其后的 32 hex salt）。
///
/// 与 python 版一致：>96 hex 的长串按 32 步长滑窗拆 64 hex，并额外取末尾窗口。
fn config_blob_candidates(blob: &[u8]) -> Vec<(String, Option<String>)> {
    if blob.is_empty() || blob.len() as u64 > CONFIG_CIPHER_BLOB_MAX {
        return Vec::new();
    }

    let decoded: Vec<u8> = blob
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ CONFIG_CIPHER_XOR_MASK[index % CONFIG_CIPHER_XOR_MASK.len()])
        .collect();

    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: HashSet<(String, Option<String>)> = HashSet::new();

    for captures in config_literal_regex().captures_iter(&decoded) {
        let Some(run) = captures.get(1) else {
            continue;
        };
        // 正则已限定 [0-9A-Fa-f]，转小写即可安全按字节切窗口
        let run = String::from_utf8_lossy(run.as_bytes()).to_ascii_lowercase();

        for start in candidate_starts(run.len()) {
            if start + 64 > run.len() {
                continue;
            }
            let key_hex = &run[start..start + 64];
            let Some(key) = decode_key_hex(key_hex) else {
                continue;
            };
            if !is_probable_key(&key) {
                continue;
            }
            let embedded_salt = if start + 96 <= run.len() {
                Some(run[start + 64..start + 96].to_string())
            } else {
                None
            };
            let item = (key_hex.to_string(), embedded_salt);
            if seen.insert(item.clone()) {
                out.push(item);
            }
        }
    }

    out
}

/// 长 hex 串的候选起点：0，然后每 32 hex 滑动一次，最后补末尾 64 hex 窗口。
fn candidate_starts(run_len: usize) -> Vec<usize> {
    let mut starts = vec![0usize];
    if run_len > 96 {
        starts.extend((0..run_len - 63).step_by(32));
        starts.push(run_len - 64);
    }
    let mut seen = HashSet::new();
    starts.retain(|start| seen.insert(*start));
    starts
}

/// 过滤明显不是 AES key 的低熵块（≥15 种字节，且不是全 0 / 全 0xff）。
fn is_probable_key(key: &[u8; 32]) -> bool {
    let distinct: HashSet<u8> = key.iter().copied().collect();
    distinct.len() >= 15 && *key != [0u8; 32] && *key != [0xffu8; 32]
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_starts, config_blob_candidates, config_literal_regex, is_probable_key,
        CONFIG_CIPHER_XOR_MASK,
    };

    fn xor(data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ CONFIG_CIPHER_XOR_MASK[i % CONFIG_CIPHER_XOR_MASK.len()])
            .collect()
    }

    /// 造一个 32 字节高熵 key 的 hex
    fn key_hex(seed: u8) -> String {
        (0..32u8)
            .map(|i| format!("{:02x}", (i.wrapping_mul(37) ^ seed).wrapping_add(11)))
            .collect()
    }

    #[test]
    fn regex_matches_hex_literal() {
        let re = config_literal_regex();
        let caps: Vec<_> = re.captures_iter(b"xx x'00ff' y'").collect();
        assert!(caps.is_empty(), "长度不足 64 hex 不应匹配");
        let text = format!("x'{}'", key_hex(3));
        let caps: Vec<_> = re.captures_iter(text.as_bytes()).collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn candidate_starts_splits_long_runs() {
        // 96 hex 及以下只有 0
        assert_eq!(candidate_starts(96), vec![0]);
        let starts = candidate_starts(160);
        assert_eq!(starts[0], 0);
        assert!(starts.contains(&96));
        assert_eq!(*starts.last().unwrap(), 160 - 64);
        // 去重且升序前导
        let unique: std::collections::HashSet<_> = starts.iter().collect();
        assert_eq!(unique.len(), starts.len());
    }

    #[test]
    fn probable_key_rejects_low_entropy() {
        assert!(!is_probable_key(&[0u8; 32]));
        assert!(!is_probable_key(&[0xffu8; 32]));
        assert!(!is_probable_key(&[0x41u8; 32]));
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        assert!(is_probable_key(&key));
    }

    #[test]
    fn blob_candidates_decode_xor_and_extract_key() {
        let key = key_hex(7);
        let plain = format!("x'{key}'");
        let blob = xor(plain.as_bytes());

        let candidates = config_blob_candidates(&blob);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, key);
        assert!(candidates[0].1.is_none());
    }

    #[test]
    fn blob_candidates_extract_embedded_salt() {
        let key = key_hex(9);
        let salt = "ab".repeat(16);
        let blob = xor(format!("x'{key}{salt}'").as_bytes());

        let candidates = config_blob_candidates(&blob);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, key);
        assert_eq!(candidates[0].1.as_deref(), Some(salt.as_str()));
    }

    #[test]
    fn blob_candidates_reject_oversized_and_empty() {
        assert!(config_blob_candidates(&[]).is_empty());
        let too_big = vec![0u8; 2048];
        assert!(config_blob_candidates(&too_big).is_empty());
    }
}
