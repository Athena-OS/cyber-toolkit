use crate::utils::*;
use log::{error, warn};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

pub fn gitclone(gitsource: Vec<&str>) {

    for url in &gitsource {
        let targetdir = "/usr/share/payloads/";
        println!("Retrieving {}...", url);
        let status = Command::new("git")
            .args(["clone", url, &(targetdir.to_owned()+url.rsplit('/').next().unwrap_or(""))])
            .status()
            .expect("Failed to execute git clone command");

        if status.success() {
            println!("Cloned successfully\n");
        } else {
            eprintln!("Failed to clone {}\n", url);
        }
    }
    install(PackageManager::Pacman, vec![
        "athena-auto-wordlists",
        "athena-fuzzdb",
        "athena-payloadsallthethings",
    ]);

    let target_file = "/usr/share/payloads/SecLists/Passwords/Leaked-Databases/rockyou.txt";
    let tar_file = "/usr/share/payloads/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz";

    if fs::metadata(target_file).is_err() {
        println!("Extracting rockyou.txt...");
        let status = Command::new("sudo")
            .arg("tar")
            .arg("-zxvf")
            .arg(tar_file)
            .arg("-C")
            .arg("/usr/share/payloads/SecLists/Passwords/Leaked-Databases")
            .status()
            .expect("Failed to execute tar command");

        if status.success() {
            println!("rockyou.txt extracted successfully!");
        } else {
            eprintln!("Failed to extract rockyou.txt");
        }
    } else {
        println!("rockyou.txt found!");
    }

    let paysource = vec![
        "/usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt",
    ];

    for paypath in &paysource {
        exec_eval(
            exec(
                "sed",
                vec![
                    String::from("-in"),
                    String::from("-e"),
                    String::from("s/^#.*$//g"),
                    String::from("-e"),
                    String::from("/^$/d"),
                    paypath.to_string(),
                ],
            ),
            "Delete commented lines from file",
        );
    }
}

pub fn install(pkgmanager: PackageManager, pkgs: Vec<&str>) {

    // Create an Arc<Mutex<bool>> for the retry flag
    let mut retry = Arc::new(Mutex::new(true)); //Just to enter the first time in the while loop
    
    let mut retry_counter = 0; // Initialize retry counter
    while *retry.lock().unwrap() && retry_counter < 15 { // retry_counter should be the number of mirrors in mirrorlist
        retry = Arc::new(Mutex::new(false));
        let retry_clone = Arc::clone(&retry); // Clone for use in the thread. I need to do this because normally I cannot define a variable above and use it inside a threadzz
        //log::info!("[ DEBUG ] Beginning retry {}", *retry.lock().unwrap());
        let mut pkgmanager_cmd = Command::new("true")
            .spawn()
            .expect("Failed to initiialize by 'true'"); // Note that the Command type below will spawn child process, so the return type is Child, not Command. It means we need to initialize a Child type element, and we can do by .spawn().expect() over the Command type. 'true' in bash is like a NOP command
        let mut pkgmanager_name = String::new();
        match pkgmanager {
            PackageManager::Pacman => {
                pkgmanager_cmd = Command::new("pacman")
                    .arg("-Syyu")
                    .arg("--needed")
                    .arg("--noconfirm")
                    .args(&pkgs)
                    //.stdout(Stdio::piped()) // Capture stdout
                    .stderr(Stdio::piped()) // Capture stderr
                    .spawn()
                    .expect("Failed to start pacman");
                pkgmanager_name = String::from("pacman");
            },
            PackageManager::Pacstrap => {
                pkgmanager_cmd = Command::new("pacstrap")
                    .arg("/mnt")
                    .args(&pkgs)
                    //.stdout(Stdio::piped()) // Capture stdout
                    .stderr(Stdio::piped()) // Capture stderr
                    .spawn()
                    .expect("Failed to start pacstrap");
                pkgmanager_name = String::from("pacstrap");
            },
            PackageManager::None => log::debug!("No package manager selected"),
        };

        //let stdout_handle = pkgmanager_cmd.stdout.take().unwrap();
        let stderr_handle = pkgmanager_cmd.stderr.take().unwrap();

        /*let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout_handle);
            for line in reader.lines() {
                let line = line.expect("Failed to read stdout");
                info!("{}", line);
                println!("{}", line); // Using also println! to print command output on screen
            }
        });*/

        let exit_status = pkgmanager_cmd.wait().expect("Failed to wait for the package manager");

        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr_handle);
            for line in reader.lines() {
                if *retry_clone.lock().unwrap() {
                    break; // Exit the for loop early if *retry is true. It means we updated the mirrorlist, we can proceed to retry the install command
                }
                let line = line.expect("Failed to read stderr");
                let exit_code = exit_status.code().unwrap_or(-1);
                if exit_code == 0 {
                    warn!(
                        "{} warn (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                    println!(
                        "{} warn (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                }
                else {
                    error!(
                        "{} err (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                    println!(
                        "{} err (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                }

                // Check if the error message contains "failed retrieving file" and "mirror"
                if line.contains("failed retrieving file") && line.contains("from") {
                    // Extract the mirror name from the error message
                    if let Some(mirror_name) = extract_mirror_name(&line) {
                        // Check if the mirror is in one of the mirrorlist files
                        if let Some(mirrorlist_file) = find_mirrorlist_file(&mirror_name, &pkgmanager_name) {
                            // Move the "Server" line within the mirrorlist file
                            if let Err(err) = move_server_line(&mirrorlist_file, &mirror_name) {
                                error!(
                                    "Failed to move 'Server' line in {}: {}",
                                    mirrorlist_file,
                                    err
                                );
                            } else {
                                // Update the retry flag within the Mutex
                                log::info!("Detected unstable mirror: {}. Retrying by a new one...", mirror_name);
                                let mut retry = retry_clone.lock().unwrap();
                                *retry = true;
                                //log::info!("[ DEBUG ] Unstable mirror retry {}", *retry);
                            }
                        }
                    }
                }
            }
        });

        // Wait for the stdout and stderr threads to finish
        //stdout_thread.join().expect("stdout thread panicked");
        stderr_thread.join().expect("stderr thread panicked");

        if !exit_status.success() {
            // Handle the error here, e.g., by logging it
            error!("The package manager failed with exit code: {}", exit_status.code().unwrap_or(-1));
        }

        // Increment the retry counter
        retry_counter += 1;

        //log::info!("[ DEBUG ] End retry {}", *retry.lock().unwrap());
    }
}

// Function to extract the mirror name from the error message
fn extract_mirror_name(error_message: &str) -> Option<String> {
    // Split the error message by whitespace to get individual words
    let words: Vec<&str> = error_message.split_whitespace().collect();

    // Iterate through the words to find the word "from" and the subsequent word
    if let Some(from_index) = words.iter().position(|&word| word == "from") {
        if let Some(mirror_name) = words.get(from_index + 1) {
            return Some(mirror_name.to_string());
        }
    }

    None // Return None if no mirror name is found
}

// Function to find the mirrorlist file containing the mirror
fn find_mirrorlist_file(mirror_name: &str, pkgmanager_name: &str) -> Option<String> {
    // Define the paths to the mirrorlist files
    let mut mirrorlist_paths: [&str; 3] = ["", "", ""];
    if pkgmanager_name == "pacstrap" {
        mirrorlist_paths = [
            "/etc/pacman.d/mirrorlist",
            "/etc/pacman.d/chaotic-mirrorlist",
            "/etc/pacman.d/blackarch-mirrorlist",
        ];
    }
    else if pkgmanager_name == "pacman" {
        mirrorlist_paths = [
            "/mnt/etc/pacman.d/mirrorlist",
            "/mnt/etc/pacman.d/chaotic-mirrorlist",
            "/mnt/etc/pacman.d/blackarch-mirrorlist",
        ];
    }

    // Iterate through the mirrorlist file paths
    for &mirrorlist_path in &mirrorlist_paths {
        // Read the content of the mirrorlist file
        if let Ok(content) = fs::read_to_string(mirrorlist_path) {
            // Check if the mirror name is contained in the file content
            if content.contains(mirror_name) {
                return Some(mirrorlist_path.to_string());
            }
        }
    }

    None // Return None if the mirror name is not found in any mirrorlist file
}

// Function to move the "Server" line in the mirrorlist file
fn move_server_line(mirrorlist_path: &str, mirror_name: &str) -> io::Result<()> {
    // Read the content of the mirrorlist file
    let mut lines: Vec<String> = Vec::new();
    let file = File::open(mirrorlist_path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        lines.push(line);
    }

    // Find the index of the last line starting with "Server"
    let last_server_index = lines.iter().rposition(|line| line.trim().starts_with("Server"));

    if let Some(last_server_index) = last_server_index {
        // Find the mirror URL line
        if let Some(mirror_url_index) = lines.iter().position(|line| line.contains(mirror_name)) {
            // Extract the mirror URL line
            let mirror_url_line = lines.remove(mirror_url_index);

            // Insert the mirror URL line after the last "Server" line
            let insert_index = last_server_index;
            lines.insert(insert_index, mirror_url_line.clone());
            // Write the modified content back to the mirrorlist file
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(mirrorlist_path)?;

            for line in lines {
                writeln!(file, "{}", line)?;
            }
            log::info!("'{}' moved at the end of {}", mirror_url_line, mirrorlist_path);
        }
    }

    Ok(())
}

pub fn uninstall(rolepkg: Vec<String>) {
    println!("Do you want to remove tools of your previous roles (y/n)?");

    let mut answer = String::new();
    let _ = io::stdin().read_line(&mut answer);

    if answer.trim().to_lowercase() == "y" {
        println!("Uninstalling any previous role tools...\n");

        for pkg in rolepkg {
            if is_package_installed(&pkg) {
                if uninstall_packages(vec![pkg]) {
                    println!("Packages uninstalled successfully.");
                } else {
                    println!("Failed to uninstall role package.");
                }
                //let roletools = get_package_dependencies(&pkg);
            }
        }
    }
}

fn is_package_installed(package_name: &str) -> bool {
    let status: ExitStatus = Command::new("pacman")
        .arg("-Qq")
        .arg(package_name)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("Failed to execute 'pacman -Qq' command.");

    // Check if the command exited successfully (status code 0) to determine if the package is installed
    status.success()
}

/*fn get_package_dependencies(package_name: &str) -> Vec<String> {
    let output = Command::new("pacman")
        .arg("-Qi")
        .arg(package_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to run pacman command")
        .stdout
        .expect("Failed to capture stdout");

    let reader = io::BufReader::new(output);

    let mut dependencies = Vec::new();
    let mut in_dependencies_section = false;

    for line in reader.lines().flatten() {
        if line.starts_with("Depends On") {
            in_dependencies_section = true;
            continue;
        }

        if in_dependencies_section {
            if let Some(dependency) = line.split_whitespace().next() {
                dependencies.push(dependency.to_string());
            } else {
                break;
            }
        }
    }

    dependencies
}*/

fn uninstall_packages(pkgs: Vec<String>) -> bool {
    for package in pkgs {
        let status: ExitStatus = Command::new("pacman")
            .arg("-Rs")
            .arg("--noconfirm")
            .arg(package.clone())
            .status()
            .expect("Failed to execute 'pacman -Rs --noconfirm' command.");

        if !status.success() {
            eprintln!("Failed to uninstall package: {}", package);
            return false;
        }
    }
    
    true
}