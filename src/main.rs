mod install;
mod utils;
use crate::install::*;
use crate::utils::*;
use std::{env, fs};
use std::io::stdin;
use std::process::Command;
use std::str;

fn detect_package_manager() -> PackageManager {
    if is_command_available("pacman") {
        PackageManager::Pacman
    } else if is_command_available("dnf") {
        PackageManager::Dnf
    } else if is_command_available("rpm-ostree") {
        PackageManager::OSTree
    }
    else {
        PackageManager::None
    }
}

fn is_command_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let manager = detect_package_manager();

    println!("Detected package manager: {:?}", manager);

    if args.len() < 2 {
        match print_banner() {
            Ok(_) => {}
            Err(error) => {
                eprintln!("Error: {}", error);
            }
        }
        get_help();
        return;
    }

    let _ = print_banner();
    let rolepkg = vec![
        String::from("role-blueteamer"),
        String::from("role-bountyhunter"),
        String::from("role-cracker"),
        String::from("role-dos"),
        String::from("role-forensic"),
        String::from("role-malware"),
        String::from("role-mobile"),
        String::from("role-network"),
        String::from("role-osint"),
        String::from("role-redteamer"),
        String::from("role-student"),
        String::from("role-webpentester"),
    ];

    uninstall(manager, rolepkg);

    match args[1].as_str() {
        "blue" => {
            if let Err(code) = install(
                manager,
                vec![
                    "role-blueteamer",
                    "clamav",
                    "cryptsetup",
                    "ddrescue",
                    "exploitdb",
                    "ext3grep",
                    "extundelete",
                    "foremost",
                    "fwbuilder",
                    "ghidra",
                    "impacket",
                    "netsniff-ng",
                    "rkhunter",
                    "sleuthkit",
                    "unhide",
                    "wireshark-qt",
                    "zaproxy",
                ],
            ) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "bugbounty" => {
            if let Err(code) = install(
                PackageManager::Pacman,
                vec![
                    "role-bountyhunter",
                    "exploitdb",
                    "findomain",
                    "gitleaks",
                    "hydra",
                    "masscan",
                    "metasploit",
                    "nikto",
                    "nmap",
                    "rustscan",
                    "sqlmap",
                    "wpscan",
                ],
            ) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "cracker" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-cracker"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "dos" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-dos"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "forensic" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-forensic"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "malware" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-malware"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "mobile" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-mobile"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "network" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-network"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "osint" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-osint"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "red" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-redteamer"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "student" => {
            if let Err(code) = install(
                PackageManager::Pacman,
                vec![
                    "role-student",
                    "aircrack-ng",
                    "binwalk",
                    "exploitdb",
                    "ghidra",
                    "hashcat",
                    "hydra",
                    "john",
                    "kismet",
                    "medusa",
                    "metasploit",
                    "mitmproxy",
                    "nasm",
                    "nikto",
                    "nmap",
                    "proxychains-ng",
                    "radare2",
                    "reaver",
                    "sqlmap",
                    "wireshark-qt",
                    "wifite",
                    "wpscan",
                ],
            ) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {}", code);
                std::process::exit(code);
            }
        }
        "web" => {
            if let Err(code) = install(PackageManager::Pacman, vec!["role-webpentester"]) {
                eprintln!("Installation failed with exit code: {}", code);
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {}", code);
                std::process::exit(code);
            }
        }
        _ => {
            println!("Invalid command: {}", args[1]);
            get_help();
        }
    }

    let mut current_user = String::new();
    let output = Command::new("who")
        .output()
        .expect("Failed to execute 'who' command");

    if output.status.success() {
        let stdout = str::from_utf8(&output.stdout).expect("Failed to parse UTF-8");
        let username = stdout.split_whitespace().next().unwrap_or("");
        current_user = username.to_string();
    } else {
        eprintln!("Error: 'who' command failed");
    }
    let setting_file = format!("/home/{}/.config/athena-welcome/settings.conf", current_user);

    if fs::metadata(setting_file.clone()).is_ok() {
        exec_eval(
            exec(
                "sed",
                vec![
                    String::from("-in"),
                    format!("s/^role=.*/role={}/g", args[1].as_str()),
                    setting_file,
                ],
            ),
            "Delete commented lines from file",
        );
    }
    println!("All done. Your role has been set!");

    let mut input = String::new();
    println!("Press Enter to continue");
    stdin().read_line(&mut input).expect("Failed to read input");
}