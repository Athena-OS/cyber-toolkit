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
    } else {
        PackageManager::None
    }
}

fn is_command_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn role_to_filebase(arg: &str) -> Option<&'static str> {
    match arg {
        "blue" => Some("blueteamer"),
        "bountyhunter" => Some("bountyhunter"),
        "cracker" => Some("cracker"),
        "dos" => Some("dos"),
        "forensic" => Some("forensic"),
        "malware" => Some("malware"),
        "mobile" => Some("mobile"),
        "network" => Some("network"),
        "osint" => Some("osint"),
        "red" => Some("redteamer"), // you may have a different name, adjust if needed
        "student" => Some("student"),
        "web" => Some("web"),
        _ => None,
    }
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

    // Initialize user config & seed roles if needed (best effort, non-fatal on error)
    if let Err(e) = utils::ensure_user_config_initialized() {
        eprintln!("Warning: could not initialize ~/.config/cyber-toolkit: {e}");
    }

    let _ = print_banner();
    let known_roles = [
        "blueteamer",
        "bugbounty",
        "cracker",
        "dos",
        "forensic",
        "malware",
        "mobile",
        "network",
        "osint",
        "redteamer",
        "student",
        "web",
    ];

    // Load role files for uninstall (silently ignore missing role files)
    let mut rolepkg_for_uninstall: Vec<Vec<String>> = Vec::new();
    for role_base in &known_roles {
        match load_role_packages(role_base) {
            Ok((pkgs, _path)) => rolepkg_for_uninstall.push(pkgs),
            Err(_) => { /* missing file -> skip */ }
        }
    }

    // Ask to uninstall previous roles
    uninstall(manager, rolepkg_for_uninstall);

    // Resolve requested role file base
    let role_arg = args[1].as_str();
    let role_filebase = match role_to_filebase(role_arg) {
        Some(rb) => rb,
        None => {
            println!("Invalid command: {role_arg}");
            get_help();
            return;
        }
    };

    // Load chosen role's packages (error if not found)
    let (pkgs, role_abs_path) = match load_role_packages(role_filebase) {
        Ok((v, p)) if !v.is_empty() => (v, p),
        Ok((_v, p)) => {
            eprintln!("Role file '{role_filebase}' at '{p}' was found but empty.");
            std::process::exit(-1);
        }
        Err(e) => {
            eprintln!("Failed to load role file for '{role_filebase}': {e}");
            std::process::exit(-1);
        }
    };
    
    let pkg_refs: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect();
    if let Err(code) = install(manager, &pkg_refs, &role_abs_path) {
        eprintln!("Installation failed with exit code: {code}");
        std::process::exit(code);
    }

    // If this role needs payloads as before, handle the special cases
    if ["bugbounty", "cracker", "red", "student", "web"].contains(&role_arg)
        && let Err(code) = getpayloads() {
            eprintln!("Failed to get payloads with exit code: {code}");
            std::process::exit(code);
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