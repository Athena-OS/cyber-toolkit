mod install;
mod utils;
use crate::install::*;
use crate::utils::*;
use std::{env, fs};
use std::io::stdin;

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        // Handle the case where no command-line arguments are provided
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
        String::from("athena-blueteamer"),
        String::from("athena-bountyhunter"),
        String::from("athena-cracker"),
        String::from("athena-dos"),
        String::from("athena-forensic"),
        String::from("athena-malware"),
        String::from("athena-mobile"),
        String::from("athena-network"),
        String::from("athena-osint"),
        String::from("athena-redteamer"),
        String::from("athena-student"),
        String::from("athena-webpentester")
        ];

    uninstall(rolepkg);
    println!("Do you want to get the fastest mirrors (y/n)?");

    let mut answer = String::new();
    stdin().read_line(&mut answer).expect("Failed to read input");

    if answer.trim().to_lowercase() == "y" {
        fastest_mirrors();
    }

    // Initialization
    let gitsource = vec![
        "https://github.com/danielmiessler/SecLists",
        "https://github.com/DragonJAR/Security-Wordlist",
    ];
    /////////////////

    match args[1].as_str() {
        "blue" => {
            install(PackageManager::Pacman, vec![
                "athena-blueteamer",
            ]);
        }
        "bugbounty" => {
            install(PackageManager::Pacman, vec![
                "athena-bountyhunter",
            ]);
            gitclone(gitsource);
        }
        "cracker" => {
            install(PackageManager::Pacman, vec![
                "athena-cracker",
            ]);
            gitclone(gitsource);
        }
        "dos" => {
            install(PackageManager::Pacman, vec![
                "athena-dos",
            ]);
        }
        "forensic" => {
            install(PackageManager::Pacman, vec![
                "athena-forensic",
            ]);
        }
        "malware" => {
            install(PackageManager::Pacman, vec![
                "athena-malware",
            ]);
        }
        "mobile" => {
            install(PackageManager::Pacman, vec![
                "athena-mobile",
            ]);
        }
        "network" => {
            install(PackageManager::Pacman, vec![
                "athena-network",
            ]);
        }
        "osint" => {
            install(PackageManager::Pacman, vec![
                "athena-osint",
            ]);
        }
        "red" => {
            install(PackageManager::Pacman, vec![
                "athena-redteamer",
            ]);
            gitclone(gitsource);
        }
        "student" => {
            install(PackageManager::Pacman, vec![
                "athena-student",
            ]);
            gitclone(gitsource);
        }
        "web" => {
            install(PackageManager::Pacman, vec![
                "athena-webpentester",
            ]);
            gitclone(gitsource);
        }
        _ => {
            println!("Invalid command: {}", args[1]);
            get_help();
        }
    }

    let sudouser = env::var("USER").unwrap_or_default();
    let setting_file = format!("/home/{}/.config/athena-welcome/settings.conf", sudouser);
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
