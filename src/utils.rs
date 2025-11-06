use clap::{ValueEnum};
use serde::{Deserialize, Serialize};
use std::process::{Command, exit, Stdio};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::env;
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, ValueEnum, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub enum PackageManager {
    #[value(name = "pacman")]
    Pacman,

    #[value(name = "None/DIY")]
    None,
}

pub fn print_banner() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = "H4sIAAAAAAAAA7XSTQ6DIBAF4D2nmE0bQxq4Avc/VQMiDD+Db2hlgQr4PgYl2mnhaltvk/lB3Je16kCmZh9V52Zs/jlVRpXnrFGXqIpVqDeohsXVW1TBwiqA4iyqQijMgiqIoiymwijIQqqU/qj6mibn2y0WUYVINmrZEvcfVayhLxEv1pSApVqf3rOPGfhiMehTJs2wa+py+qSVmabrvZXWnqob5tq4EA7R7c9lBD3753KtnUTnxfKhsQhqQ0ppdY5vjX0Uf14Mmz765Y2KtyGmZOXReMIp2Ka+rldTiw2UnlzszRejmEcVIQoAAA==";

    // Decode using base64
    let mut child = Command::new("base64")
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(encoded.as_bytes())?;
    }
    let output = child.wait_with_output()?;

    // Decompress using gunzip
    let mut gunzip_child = Command::new("gunzip")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if let Some(ref mut stdin) = gunzip_child.stdin {
        stdin.write_all(&output.stdout)?;
    }
    let gunzip_output = gunzip_child.wait_with_output()?;

    if gunzip_output.status.success() {
        let decompressed = String::from_utf8_lossy(&gunzip_output.stdout).into_owned().replace("\\x1b", "\x1b"); // .replace is needed to apply the colors on the banner string
        
        let mut stdout = io::stdout();
        writeln!(stdout, "{decompressed}")?;
    } else {
        eprintln!("'gunzip' command failed");
    }

    Ok(())
}

pub fn get_help() {
    // Display Help
    println!("Set your Cyber Security role.");
    println!();
    println!("Options:");
    println!("blue                            Set Blue Teamer role.");
    println!("bountyhunter                    Set Bug Bounty Hunter role.");
    println!("cracker                         Set Cracker Specialist role.");
    println!("dos                             Set DoS Tester role.");
    println!("forensic                        Set Forensic Analyst role.");
    println!("malware                         Set Malware Analyst role.");
    println!("mobile                          Set Mobile Analyst role.");
    println!("network                         Set Network Analyst role.");
    println!("osint                           Set OSINT Specialist role.");
    println!("red                             Set Red Teamer role.");
    println!("student                         Set Enthusiast Student role.");
    println!("web                             Set Web Pentester role.");
    println!();
    println!("Usage Examples:");
    println!("{}", env::args().next().unwrap());
    println!("{} blue", env::args().next().unwrap());
    println!("{} red", env::args().next().unwrap());
    println!("{} osint", env::args().next().unwrap());
    println!("{} student", env::args().next().unwrap());
}

pub fn exec(command: &str, args: Vec<String>) -> io::Result<()> {
    let mut child = Command::new(command)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped()) // we'll log it via info!()
        .stderr(Stdio::piped()) // we'll capture it for error reporting
        .spawn()?;

    // --- log stdout line-by-line via info!() ---
    let mut stdout = child.stdout.take().expect("piped stdout");
    let stdout_handle = std::thread::spawn(move || -> io::Result<()> {
        let mut reader = BufReader::new(&mut stdout);
        let mut line = Vec::<u8>::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            if n == 0 { break; }
            let text = String::from_utf8_lossy(&line).trim_end_matches(&['\r','\n'][..]).to_string();
            println!("{text}");
        }
        Ok(())
    });

    // --- capture stderr fully (no live print) ---
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stderr_handle = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });

    let status = child.wait()?;
    stdout_handle.join().unwrap()?;              // propagate stdout I/O errors
    let stderr_buf = stderr_handle.join().unwrap()?; // captured stderr

    if status.success() {
        Ok(())
    } else {
        let err_text = String::from_utf8_lossy(&stderr_buf).trim().to_string();
        let msg = if err_text.is_empty() {
            format!("{command} {args:?} exited with {status}")
        } else {
            format!("{command} {args:?} failed: {err_text}")
        };
        Err(io::Error::other(msg))
    }
}

pub fn exec_eval(result: Result<(), std::io::Error>, logmsg: &str) {
    match result {
        Ok(()) => println!("{logmsg}"),
        Err(e) => {
            let code = e.raw_os_error().unwrap_or(1);
            crash(format!("{e}"), code);
        }
    }
}

pub fn load_role_packages(role: &str) -> Result<(Vec<String>, String), io::Error> {
    // Try to initialize user config (best effort)
    let mut home_first: Option<String> = None;
    if let Ok(user_cfg) = ensure_user_config_initialized() {
        let p = user_cfg.join("roles").join(format!("{role}.role"));
        home_first = Some(p.to_string_lossy().into_owned());
    }

    let mut candidates = Vec::<String>::new();

    // 1) ~/.config/cyber-toolkit/roles/<role>.role  (FIRST)
    if let Some(p) = home_first {
        candidates.push(p);
    }

    // 2) ./<role>.role
    candidates.push(format!("./{role}.role"));

    // 3) ./roles/<role>.role
    candidates.push(format!("./roles/{role}.role"));

    // 4) /usr/share/cyber-toolkit/roles/<role>.role
    candidates.push(format!("/usr/share/cyber-toolkit/roles/{role}.role"));

    for path in &candidates {
        if let Ok(content) = fs::read_to_string(path) {
            let mut pkgs: Vec<String> = Vec::new();
            for line in content.lines() {
                let clean = line.split('#').next().unwrap_or("").trim();
                if !clean.is_empty() {
                    pkgs.push(clean.to_string());
                }
            }

            let abs = fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
            let abs_str = abs.to_string_lossy().into_owned();
            return Ok((pkgs, abs_str));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Role file for '{role}' not found (checked: {candidates:?})"),
    ))
}

fn home_for_username(username: &str) -> Option<PathBuf> {
    if username.is_empty() {
        return None;
    }
    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[0] == username {
                return Some(PathBuf::from(parts[5]));
            }
        }
    }
    None
}

/// Detect the "real" user's home even if running under sudo or su.
fn detect_target_home() -> io::Result<PathBuf> {
    // 1) XDG_RUNTIME_DIR => usually /run/user/<UID>
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let xdg = xdg.trim();
        if !xdg.is_empty() {
            // try to extract the UID from a path like /run/user/1000
            if let Some(pos) = xdg.rfind('/') {
                let last = &xdg[pos + 1..];
                if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit())
                    && last != "0"
                        && let Some(user) = username_for_uid(last)
                            && let Some(home) = home_for_username_from_passwd(&user) {
                                return Ok(home);
                            }
            }
        }
    }

    // 2) try to inspect /run/user for a single non-root entry (best-effort)
    if let Ok(entries) = std::fs::read_dir("/run/user") {
        for e in entries.flatten() {
            if let Ok(fname) = e.file_name().into_string()
                && fname != "0" && fname.chars().all(|c| c.is_ascii_digit())
                    && let Some(user) = username_for_uid(&fname)
                        && let Some(home) = home_for_username_from_passwd(&user) {
                            return Ok(home);
                        }
        }
    }

    // 3. Fallback to $HOME (root in worst case)
    if let Ok(home_env) = std::env::var("HOME") {
        return Ok(PathBuf::from(home_env));
    }

    // 4. Last resort
    Ok(PathBuf::from("/root"))
}

fn dir_is_empty(p: &Path) -> io::Result<bool> {
    match fs::read_dir(p) {
        Ok(mut it) => Ok(it.next().is_none()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if !src.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Source directory not found: {}", src.display()),
        ));
    }
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ty.is_file() {
            // create parent dir(s) just in case
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Ensure ~/.config/cyber-toolkit exists, and if it's empty,
/// copy /usr/share/cyber-toolkit/roles into it.
pub fn ensure_user_config_initialized() -> io::Result<PathBuf> {
    let target_home = detect_target_home()?;
    let user_cfg = target_home.join(".config").join("cyber-toolkit");
    fs::create_dir_all(&user_cfg)?; // always ensure it exists

    // Source roles (if present on the system)
    let src_roles = Path::new("/usr/share/cyber-toolkit/roles");

    // Destination roles under the user's config
    let dst_roles = user_cfg.join("roles");

    // If ~/.config/cyber-toolkit is completely empty, seed roles.
    // Also seed when roles/ doesn't exist or roles/ exists but is empty.
    let should_seed_roles =
        dir_is_empty(&user_cfg)? ||
        !dst_roles.exists() ||
        dir_is_empty(&dst_roles)?;

    if should_seed_roles {
        if src_roles.exists() {
            // Ensure destination directory exists, then copy
            fs::create_dir_all(&dst_roles)?;
            copy_dir_recursive(src_roles, &dst_roles)?;
            println!("Copied roles to {}", dst_roles.display());
        } else {
            // No system roles to copy; at least ensure the directory exists
            fs::create_dir_all(&dst_roles)?;
        }
    }

    Ok(user_cfg)
}

// helper: resolve username from a numeric UID string by scanning /etc/passwd
fn username_for_uid(uid: &str) -> Option<String> {
    if uid.is_empty() { return None; }
    if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            if line.starts_with('#') || line.trim().is_empty() { continue; }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2] == uid {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

// helper: get home path for username (reuse existing home_for_username if you have it)
fn home_for_username_from_passwd(username: &str) -> Option<std::path::PathBuf> {
    home_for_username(username)
}

pub fn crash<S: AsRef<str>>(a: S, b: i32) -> ! {
    println!("{}", a.as_ref());
    exit(b);
}