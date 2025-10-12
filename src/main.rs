mod install;
mod roles;
mod utils;
use crate::install::*;
use crate::roles::*;
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

    println!("Detected package manager: {manager:?}");

    if args.len() < 2 {
        match print_banner() {
            Ok(_) => {}
            Err(error) => {
                eprintln!("Error: {error}");
            }
        }
        get_help();
        return;
    }

    let _ = print_banner();
    let rolepkg = vec![
        ROLE_BLUETEAMER,
        ROLE_BOUNTYHUNTER,
        ROLE_CRACKER,
        ROLE_DOS,
        ROLE_FORENSIC,
        ROLE_MALWARE,
        ROLE_MOBILE,
        ROLE_NETWORK,
        ROLE_OSINT,
        ROLE_REDTEAMER,
        ROLE_STUDENT,
        ROLE_WEBPENTESTER,
    ];

    uninstall(manager, rolepkg);

    match args[1].as_str() {
        "blue" => {
            if let Err(code) = install(manager, ROLE_BLUETEAMER) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "bugbounty" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_BOUNTYHUNTER) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {code}");
                std::process::exit(code);
            }
        }
        "cracker" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_CRACKER) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {code}");
                std::process::exit(code);
            }
        }
        "dos" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_DOS) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "forensic" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_FORENSIC) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "malware" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_MALWARE) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "mobile" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_MOBILE) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "network" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_NETWORK) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "osint" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_OSINT) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
        }
        "red" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_REDTEAMER) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {code}");
                std::process::exit(code);
            }
        }
        "student" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_STUDENT) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {code}");
                std::process::exit(code);
            }
        }
        "web" => {
            if let Err(code) = install(PackageManager::Pacman, ROLE_WEBPENTESTER) {
                eprintln!("Installation failed with exit code: {code}");
                std::process::exit(code);
            }
            if let Err(code) = getpayloads() {
                eprintln!("Failed to get payloads with exit code: {code}");
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
    let setting_file = format!("/home/{current_user}/.config/athena-welcome/settings.conf");

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