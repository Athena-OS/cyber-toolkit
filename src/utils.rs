use clap::{ValueEnum};
use serde::{Deserialize, Serialize};
use std::process::{Command, exit, Stdio};
use std::io::{self, Write};
use std::env;

#[derive(Debug, ValueEnum, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub enum PackageManager {
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
        writeln!(stdout, "{}", decompressed)?;
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
    println!("bugbounty                       Set Bug Bounty Hunter role.");
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

pub fn exec(command: &str, args: Vec<String>) -> Result<std::process::ExitStatus, std::io::Error> {
    let returncode = Command::new(command).args(args).status();
    returncode
}

pub fn exec_eval(
    return_code: std::result::Result<std::process::ExitStatus, std::io::Error>,
    logmsg: &str,
) {
    match &return_code {
        Ok(_) => {
            //println!("{}", logmsg);
        }
        Err(e) => {
            crash(
                format!("{}  ERROR: {}", logmsg, e),
                return_code.unwrap_err().raw_os_error().unwrap(),
            );
        }
    }
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