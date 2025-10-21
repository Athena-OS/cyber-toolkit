use clap::{ValueEnum};
use serde::{Deserialize, Serialize};
use std::process::{Command, exit, Stdio};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::env;
use std::fs;

#[derive(Debug, ValueEnum, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub enum PackageManager {
    #[value(name = "dnf")]
    Dnf,

    #[value(name = "rpm-ostree")]
    OSTree,

    #[value(name = "pacman")]
    Pacman,

    #[value(name = "pacstrap")]
    Pacstrap,

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
    let candidates = [
        format!("./{role}.role"),
        format!("./roles/{role}.role"),
        format!("/usr/share/cyber-toolkit/roles/{role}.role"),
    ];

    for path in &candidates {
        if let Ok(content) = fs::read_to_string(path) {
            let mut pkgs: Vec<String> = Vec::new();
            for line in content.lines() {
                // Remove inline comments after '#', then trim
                let clean = line.split('#').next().unwrap_or("").trim();
                if !clean.is_empty() {
                    pkgs.push(clean.to_string());
                }
            }

            // Try to make it absolute; if it fails, keep the found path
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

pub fn crash<S: AsRef<str>>(a: S, b: i32) -> ! {
    println!("{}", a.as_ref());
    exit(b);
}

/*
pub fn fastest_mirrors() {
    println!("Getting fastest BlackArch mirrors for your location");
    exec_eval(
        exec(
            "rate-mirrors",
            vec![
                String::from("--concurrency"),
                String::from("40"),
                String::from("--disable-comments"),
                String::from("--allow-root"),
                String::from("--save"),
                String::from("/etc/pacman.d/blackarch-mirrorlist"),
                String::from("blackarch"),
            ],
        ),
        "Getting fastest mirrors from BlackArch",
    );
}
*/