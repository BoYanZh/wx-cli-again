use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config;
use crate::scanner::{self, KeyEntry, ScanOptions};

pub fn cmd_init(force: bool, hook_seconds: Option<u64>) -> Result<()> {
    // 查找 config.json
    let config_path = find_or_create_config_path();

    // 检查是否已初始化
    if !force && config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                let db_dir = cfg.get("db_dir").and_then(|v| v.as_str()).unwrap_or("");
                let keys_file = cfg
                    .get("keys_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all_keys.json");
                let keys_path = resolve_keys_path(&config_path, keys_file);
                if !db_dir.is_empty()
                    && !db_dir.contains("your_wxid")
                    && Path::new(db_dir).exists()
                    && keys_path.exists()
                {
                    println!("已初始化，数据目录: {}", db_dir);
                    println!("如需重新扫描密钥，使用 --force");
                    // 仍检查磁盘上是否有未收录的分片
                    if let Ok(existing) = load_existing_entries(&keys_path, Path::new(db_dir)) {
                        let missing = scanner::missing_encrypted_dbs(Path::new(db_dir), &existing);
                        if !missing.is_empty() {
                            let critical: Vec<_> = missing
                                .iter()
                                .filter(|n| scanner::is_critical_missing_db(n))
                                .collect();
                            println!(
                                "[wx] 警告：磁盘上仍有 {} 个加密 DB 没有密钥（关键 {} 个，例如 {}）。\n\
                                 运行 {} 重新提取，{}。",
                                missing.len(),
                                critical.len(),
                                critical
                                    .first()
                                    .copied()
                                    .or(missing.first())
                                    .map(|s| s.as_str())
                                    .unwrap_or(""),
                                config::RECOMMENDED_KEY_EXTRACT,
                                config::COLD_SHARD_ADVICE
                            );
                        }
                    }
                    return Ok(());
                }
            }
        }
    }

    // Step 1: 解析 db_dir —— 已有有效配置时优先沿用，避免多账号下 auto-detect 切错库。
    let db_dir = resolve_db_dir(&config_path)?;
    println!("数据目录: {}", db_dir.display());

    // 读取已有密钥（验证仍有效的保留，避免 force 扫描不全时丢 key）
    let keys_file_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("all_keys.json");
    let existing_entries = load_existing_entries(&keys_file_path, &db_dir).unwrap_or_default();
    if !existing_entries.is_empty() {
        println!(
            "已有 {} 个仍可解密的密钥，将与新扫描结果合并",
            existing_entries.len()
        );
    }

    // Step 2: 扫描密钥
    println!("扫描加密密钥…");
    let mut opts = ScanOptions {
        known: &existing_entries,
        ..ScanOptions::default()
    };
    if let Some(secs) = hook_seconds {
        opts.hook_seconds = secs;
        opts.auto_hook = secs > 0;
    }
    let scanned = scanner::scan_keys_with_options(&db_dir, opts)?;
    // scan 内部已合并 known；再 merge 一次保证兜底
    let entries = scanner::merge_key_entries(&scanned, &existing_entries);

    if entries.is_empty() {
        let msg = format!(
            "没有任何候选 key 能解密所选数据目录中的数据库，已保留现有配置和 key 文件。\n\
             当前数据目录: {}\n\
             如果本机登录过多个微信账号，请确认该目录属于当前正在运行的账号；\
             退出其他账号并让当前账号产生一条新消息后，再运行：\n\
             {}\n\
             冷分片（久未打开的 message_N.db）用同一条命令，{}。",
            db_dir.display(),
            config::RECOMMENDED_KEY_EXTRACT,
            config::COLD_SHARD_ADVICE
        );
        // Windows: 明确 hook 参数无效；macOS/Linux: 不加任何内容，保持原文案
        #[cfg(windows)]
        let msg = format!("{}\n{}", msg, config::KEY_EXTRACT_PLATFORM_NOTE);
        bail!("{}", msg);
    }

    // === 权限边界 ===
    // 扫描完成后立即 drop 到调用用户身份，后续文件写入都是用户属主。
    #[cfg(unix)]
    drop_privileges_if_sudo()?;

    // 确保父目录存在（如 ~/.wx-cli/），必须在任何写入之前
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建目录失败: {}", parent.display()))?;
    }

    // Step 3: 保存 all_keys.json（合并后的完整集合）
    let mut keys_json = serde_json::Map::new();
    for entry in &entries {
        keys_json.insert(
            entry.db_name.clone(),
            json!({
                "enc_key": entry.enc_key,
            }),
        );
    }
    std::fs::write(&keys_file_path, serde_json::to_string_pretty(&keys_json)?)
        .context("写入 all_keys.json 失败")?;
    println!(
        "成功保存 {} 个数据库密钥（本次新匹配 {}）",
        entries.len(),
        scanned.len()
    );
    println!("密钥已保存: {}", keys_file_path.display());

    let missing = scanner::list_missing_encrypted_dbs(&db_dir, &entries);
    let critical: Vec<_> = missing
        .iter()
        .filter(|m| scanner::is_critical_missing_db(&m.rel))
        .collect();
    if !missing.is_empty() {
        println!(
            "[wx] 警告：仍有 {} 个加密 DB 没有密钥（其中 {} 个影响聊天完整性）：",
            missing.len(),
            critical.len()
        );
        for m in missing.iter().take(12) {
            let tag = if scanner::is_critical_missing_db(&m.rel) {
                " [关键]"
            } else {
                ""
            };
            println!(
                "  - {} ({}){}",
                m.rel,
                scanner::format_db_size(m.size),
                tag
            );
        }
        if missing.len() > 12 {
            println!("  … 另有 {} 个", missing.len() - 12);
        }
        if !critical.is_empty() {
            println!(
                "补齐关键分片：{}\n{}。",
                config::RECOMMENDED_KEY_EXTRACT,
                config::COLD_SHARD_ADVICE
            );
        }
    }

    // Step 4: 保存 config.json
    let mut cfg = HashMap::new();
    if config_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&config_path) {
            if let Ok(v) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&c) {
                for (k, val) in v {
                    cfg.insert(k, val);
                }
            }
        }
    }
    cfg.insert("db_dir".into(), json!(db_dir.to_string_lossy()));
    cfg.entry("keys_file".into())
        .or_insert_with(|| json!("all_keys.json"));
    cfg.entry("decrypted_dir".into())
        .or_insert_with(|| json!("decrypted"));

    std::fs::write(&config_path, serde_json::to_string_pretty(&cfg)?)
        .context("写入 config.json 失败")?;
    println!("配置已保存: {}", config_path.display());
    println!("初始化完成，可以使用 wx sessions / wx history 等命令了");

    #[cfg(target_os = "macos")]
    {
        println!();
        println!("[macOS] 说明：");
        println!("  · SIP 无需关闭；wx-cli 不会自动 ad-hoc 重签 WeChat.app。");
        println!(
            "  · 官网部分 4.x 包本身已是 ad-hoc，可直接用户态 LLDB hook，无需 sudo 重签。"
        );
        println!(
            "  · 官方 Hardened Runtime 包：内存扫描请 sudo；补冷分片用 --hook-seconds。"
        );
    }

    Ok(())
}

fn resolve_keys_path(config_path: &Path, keys_file: &str) -> PathBuf {
    if Path::new(keys_file).is_absolute() {
        PathBuf::from(keys_file)
    } else {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(keys_file)
    }
}

/// 优先使用 config 里已配置且仍存在的 `db_dir`；否则再 auto-detect。
///
/// 多账号场景下，`auto_detect` 按 mtime 选最新目录可能切到闲置号，
/// 导致 force 提取时已有密钥全部校验失败、用户误以为密钥丢了。
fn resolve_db_dir(config_path: &Path) -> Result<PathBuf> {
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(dir) = cfg.get("db_dir").and_then(|v| v.as_str()) {
                    let p = PathBuf::from(dir);
                    if !dir.is_empty()
                        && !dir.contains("your_wxid")
                        && p.is_dir()
                    {
                        // 若磁盘上另有更新的账号目录，仅提示，不擅自切换
                        if let Some(detected) = config::auto_detect_db_dir() {
                            if detected != p {
                                eprintln!(
                                    "[wx] 提示：检测到更新的微信数据目录 {}，\n\
                                     当前仍使用已配置的 {}。\n\
                                     若要切换账号，请编辑 config.json 的 db_dir 后重新 init。",
                                    detected.display(),
                                    p.display()
                                );
                            }
                        }
                        return Ok(p);
                    }
                }
            }
        }
    }
    println!("检测微信数据目录...");
    config::auto_detect_db_dir()
        .context("未能自动检测到微信数据目录\n请手动编辑 config.json 中的 db_dir 字段")
}

/// 加载已有 all_keys.json，并丢弃无法再解密对应 DB 的条目。
fn load_existing_entries(keys_path: &Path, db_dir: &Path) -> Result<Vec<KeyEntry>> {
    if !keys_path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(keys_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;
    let mut out = Vec::new();
    let Some(obj) = value.as_object() else {
        return Ok(out);
    };
    for (db_name, v) in obj {
        if db_name.starts_with('_') {
            continue;
        }
        let enc_key = if let Some(s) = v.as_str() {
            s.to_string()
        } else if let Some(o) = v.as_object() {
            o.get("enc_key")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            continue;
        };
        if enc_key.len() != 64 {
            continue;
        }
        let db_path = db_dir.join(db_name);
        if !db_path.exists() {
            continue;
        }
        let Some(key) = scanner::decode_key_hex_pub(&enc_key) else {
            continue;
        };
        if crate::crypto::validate_raw_key_for_db(&db_path, &key) {
            let salt = scanner::read_db_salt(&db_path).unwrap_or_default();
            out.push(KeyEntry {
                db_name: db_name.replace('\\', "/"),
                enc_key: enc_key.to_lowercase(),
                salt,
            });
        }
    }
    Ok(out)
}

/// 如果当前以 root 身份运行且是通过 sudo 启动的，drop 到调用用户身份，
/// 并迁移旧版本遗留的 root 属主 `~/.wx-cli/`。
///
/// 只影响本进程；daemon（后续 fork）会继承调用用户身份。
#[cfg(unix)]
fn drop_privileges_if_sudo() -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // 当前不是 root（用户直接以非 root 跑的 `wx init`）→ 什么都不做
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let sudo_uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    let sudo_gid: Option<u32> = std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok());
    let (uid, gid) = match (sudo_uid, sudo_gid) {
        (Some(u), Some(g)) if u != 0 => (u, g),
        // 直接以 root 登陆（非 sudo），没有"调用用户"可还原 → 保持 root
        _ => return Ok(()),
    };

    // 迁移旧版本遗留：如果 ~/.wx-cli/ 已存在且属 root，把它 chown 回调用用户，
    // 顺便把 raw key 文件的权限也收紧到 0600（旧版默认 0644，世界可读等于泄露）。
    // 这些必须在 setuid 之前做：chown 需要 root，chmod 也只有属主或 root 能改。
    let cli_dir = config::cli_dir();
    if cli_dir.exists() {
        let _ = chown_recursive(&cli_dir, uid, gid);
        let _ = tighten_perms(&cli_dir);
    }

    // 设置 umask，让后续 create 出来的文件/目录默认是 0600 / 0700。
    unsafe {
        libc::umask(0o077);
    }

    // 必须先 setgid 再 setuid：一旦 uid 降下来就没法再改 gid 了。
    unsafe {
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({}) 失败: {}", gid, std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({}) 失败: {}", uid, std::io::Error::last_os_error());
        }
    }

    // chown 递归实现
    fn chown_recursive(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        chown_one(path, uid, gid)?;
        let md = std::fs::symlink_metadata(path)?;
        if md.is_dir() {
            for entry in std::fs::read_dir(path)? {
                chown_recursive(&entry?.path(), uid, gid)?;
            }
        }
        Ok(())
    }
    fn chown_one(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL")
        })?;
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// 目录收紧到 0700，所有 *.json 文件（含 all_keys.json 这类 raw key）收紧到 0600。
    fn tighten_perms(cli_dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cli_dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(cli_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(())
    }

    Ok(())
}

fn find_or_create_config_path() -> std::path::PathBuf {
    // 如果当前工作目录或可执行文件目录已有 config.json，沿用它（支持便携模式）
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("config.json");
        if p.exists() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.json");
            if p.exists() {
                return p;
            }
        }
    }
    // 默认写入 ~/.wx-cli/config.json（与 load_config 的最终查找路径保持一致）
    config::cli_dir().join("config.json")
}
