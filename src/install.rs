use crate::utils::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, stdin, BufRead, BufReader, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

//pub fn gitclone(gitsource: Vec<&str>) {
pub fn getpayloads() -> Result<(), i32> {
    install(PackageManager::Pacman, vec![
        "autowordlists",
        "fuzzdb",
        "payloadsallthethings",
        "seclists",
        "security-wordlist",
    ])?;

    let target_file = "/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt";
    let tar_file = "/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz";

    if fs::metadata(target_file).is_err() {
        println!("Extracting rockyou.txt...");
        let status = Command::new("tar")
            .arg("-zxvf")
            .arg(tar_file)
            .arg("-C")
            .arg("/usr/share/payloads/seclists/Passwords/Leaked-Databases")
            .status()
            .expect("Failed to execute tar command");

        if status.success() {
            println!("rockyou.txt extracted successfully!");
        } else {
            eprintln!("Failed to extract rockyou.txt");
            return Err(-1); // Propagate error with a custom exit code
        }
    } else {
        println!("rockyou.txt found!");
    }

    let paysource = vec![
        "/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
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

    Ok(())
}

pub fn install(pkgmanager: PackageManager, pkgs: Vec<&str>) -> Result<(), i32> {

    // Create an Arc<Mutex<bool>> for the retry flag
    let mut retry = Arc::new(Mutex::new(true)); //Just to enter the first time in the while loop
    
    let mut retry_counter = 0; // Initialize retry counter
    while *retry.lock().unwrap() && retry_counter < 15 { // retry_counter should be the number of mirrors in mirrorlist
        retry = Arc::new(Mutex::new(false));
        let retry_clone = Arc::clone(&retry); // Clone for use in the thread. I need to do this because normally I cannot define a variable above and use it inside a threadzz
        //println!("[ DEBUG ] Beginning retry {}", *retry.lock().unwrap());
        let mut pkgmanager_cmd = Command::new("true")
            .spawn()
            .expect("Failed to initiialize by 'true'"); // Note that the Command type below will spawn child process, so the return type is Child, not Command. It means we need to initialize a Child type element, and we can do by .spawn().expect() over the Command type. 'true' in bash is like a NOP command
        let mut pkgmanager_name = String::new();
        match pkgmanager {
            PackageManager::Dnf => {
                Command::new("dnf")
                    .arg("makecache")
                    .arg("--refresh")
                    .status()
                    .expect("Failed to refresh dnf cache");
                pkgmanager_cmd = Command::new("dnf")
                    .arg("install")
                    .arg("-y")
                    .args(&pkgs)
                    //.stdout(Stdio::piped()) // Capture stdout
                    .stderr(Stdio::piped()) // Capture stderr
                    .spawn()
                    .expect("Failed to start dnf");
                pkgmanager_name = String::from("dnf");
            },
            PackageManager::OSTree => {
                Command::new("rpm-ostree")
                    .arg("refresh-md")
                    .status()
                    .expect("Failed to refresh rpm-ostree cache");
                pkgmanager_cmd = Command::new("rpm-ostree")
                    .arg("install")
                    .args(&pkgs)
                    //.stdout(Stdio::piped()) // Capture stdout
                    .stderr(Stdio::piped()) // Capture stderr
                    .spawn()
                    .expect("Failed to start rpm-ostree");
                pkgmanager_name = String::from("rpm-ostree");
            },
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
            PackageManager::None => println!("No package manager selected"),
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
                    println!(
                        "{} warn (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                }
                else {
                    println!(
                        "{} err (exit code {}): {}",
                        pkgmanager_name,
                        exit_code,
                        line
                    );
                }
                if pkgmanager_name == "pacman" || pkgmanager_name == "pacstrap" {
                    //line = "error: miaomiao: signature from \"You know (MiaoArch Developer) <youknow@miaosecurity.bau>\" is invalid".to_string(); // DEBUG TEST
                    // Check if the error message contains "failed retrieving file" and "mirror"
                    if line.contains("failed retrieving file") && line.contains("from") {
                        // Extract the mirror name from the error message
                        if let Some(mirror_name) = extract_mirror_name(&line) {
                            // Check if the mirror is in one of the mirrorlist files
                            if let Some(mirrorlist_file) = find_mirrorlist_file(&mirror_name) {
                                // Move the "Server" line within the mirrorlist file
                                if let Err(err) = move_server_line(&mirrorlist_file, &mirror_name) {
                                    println!(
                                        "Failed to move 'Server' line in {}: {}",
                                        mirrorlist_file,
                                        err
                                    );
                                } else {
                                    // Update the retry flag within the Mutex
                                    println!("Detected unstable mirror: {}. Retrying by a new one...", mirror_name);
                                    let mut retry = retry_clone.lock().unwrap();
                                    *retry = true;
                                    //println!("[ DEBUG ] Unstable mirror retry {}", *retry);
                                }
                            }
                        }
                    }
                    else if line.contains("signature from") && line.contains("is invalid") {
                        let mut mirrorlist_filename = String::new();
                        let extracted_name = extract_package_name(&line);
                        if extracted_name == "blackarch" { // the error 'signature from xxx is invalid' could be also related to the repository itslef instead of a package
                            mirrorlist_filename = String::from("/etc/pacman.d/blackarch-mirrorlist");
                        }
                        else { // if the error 'signature from xxx is invalid'
                            let repository = get_repository_name(&extracted_name);
                            println!("Package {} found in repository: {}", extracted_name, repository);

                            if repository == "core" || repository == "extra" || repository == "community" || repository == "multilib" {
                                mirrorlist_filename = String::from("/etc/pacman.d/mirrorlist");
                            }
                            if repository == "blackarch" {
                                mirrorlist_filename = String::from("/etc/pacman.d/blackarch-mirrorlist");
                            }
                            if repository == "chaotic-aur" {
                                mirrorlist_filename = String::from("/etc/pacman.d/chaotic-mirrorlist");
                            }
                        }

                        match get_first_mirror_name(&mirrorlist_filename) {
                            Ok(mirror_name) => {
                                println!("Mirror Name: {}", mirror_name);
                                if let Err(err) = move_server_line(&mirrorlist_filename, &mirror_name) {
                                    println!(
                                        "Failed to move 'Server' line in {}: {}",
                                        mirrorlist_filename,
                                        err
                                    );
                                } else {
                                    // Update the retry flag within the Mutex
                                    println!("Detected invalid signature key in mirror: {}. Retrying by a new one...", mirror_name);
                                    let mut retry = retry_clone.lock().unwrap();
                                    *retry = true;
                                    //log::info!("[ DEBUG ] Invalid signature key in mirror retry {}", *retry);
                                }
                            }
                            Err(err) => eprintln!("Error: {}", err),
                        }
                    }
                    else if exit_code != 0 {
                        return Err(-1);
                    }
                }
            }
            Ok(())
        });

        // Wait for the stdout and stderr threads to finish
        //stdout_thread.join().expect("stdout thread panicked");
        // Handle the result of stderr_thread.join()
        let stderr_thread_result = stderr_thread.join();
        match stderr_thread_result {
            Ok(res) => {
                res?
            }
            Err(_) => {
                eprintln!("stderr thread panicked");
                return Err(-1); // Return an appropriate error code
            }
        }

        if !exit_status.success() {
            println!(
                "The package manager failed with exit code: {}",
                exit_status.code().unwrap_or(-1)
            );
            return Err(exit_status.code().unwrap_or(-1));
        }

        retry_counter += 1;
    }
    Ok(())
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
fn find_mirrorlist_file(mirror_name: &str) -> Option<String> {
    // Define the paths to the mirrorlist files
    let mirrorlist_paths = [
        "/etc/pacman.d/mirrorlist",
        "/etc/pacman.d/chaotic-mirrorlist",
        "/etc/pacman.d/blackarch-mirrorlist",
    ];

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
            println!("'{}' moved at the end of {}", mirror_url_line, mirrorlist_path);
        }
    }

    Ok(())
}

pub fn uninstall(pkgmanager: PackageManager, rolepkg: Vec<String>) {
    println!("Do you want to remove tools of your previous roles (y/n)?");

    let mut answer = String::new();
    stdin().read_line(&mut answer).expect("Failed to read input");

    if answer.trim().to_lowercase() == "y" {
        println!("Uninstalling any previous role tools...\n");

        for pkg in rolepkg {
            if is_package_installed(pkgmanager, &pkg) {
                if uninstall_packages(pkgmanager, vec![pkg]) {
                    println!("Packages uninstalled successfully.");
                } else {
                    println!("Failed to uninstall role package.");
                }
                //let roletools = get_package_dependencies(&pkg);
            }
        }
    }
}

fn is_package_installed(pkgmanager: PackageManager, package_name: &str) -> bool {
    let status: ExitStatus = match pkgmanager {
        PackageManager::Dnf | PackageManager::OSTree => {
            Command::new("rpm")
                .arg("-q")
                .arg(package_name)
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .expect("Failed to execute rpm -q")
        },        
        PackageManager::Pacman => {
            Command::new("pacman")
                .arg("-Qq")
                .arg(package_name)
                .stderr(Stdio::null())
                .status()
                .expect("Failed to execute pacman -Qq")
        },
        _ => {
            eprintln!("Unsupported package manager for checking installed packages.");
            return false;
        }
    };

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


fn uninstall_packages(pkgmanager: PackageManager, pkgs: Vec<String>) -> bool {
    for package in pkgs {
        let status: ExitStatus = match pkgmanager {
            PackageManager::Dnf => {
                Command::new("dnf")
                    .arg("remove")
                    .arg("-y")
                    .arg(&package)
                    .status()
                    .expect("Failed to execute dnf uninstall")
            },
            PackageManager::OSTree => {
                Command::new("rpm-ostree")
                    .arg("uninstall")
                    .arg(&package)
                    .status()
                    .expect("Failed to execute rpm-ostree uninstall")
            },            
            PackageManager::Pacman => {
                Command::new("pacman")
                    .arg("-Rs")
                    .arg("--noconfirm")
                    .arg(&package)
                    .status()
                    .expect("Failed to execute pacman uninstall")
            },
            _ => {
                eprintln!("Unsupported package manager for uninstall.");
                return false;
            }
        };

        if !status.success() {
            eprintln!("Failed to uninstall package: {}", package);
            return false;
        }
    }

    true
}

fn get_first_mirror_name(filename: &str) -> Result<String, io::Error> {
    let file = File::open(filename)?;
    
    for line in BufReader::new(file).lines() {
        let line = line?; // Unwrap the Result to get the line directly
        if let Some(equals_index) = line.find('=') {
            let trimmed_line = line[..equals_index].trim();
            if trimmed_line == "Server" {
                let mirror_url = line[equals_index + 1..].trim();
                return Ok(mirror_url.to_string());
            }
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "Mirror not found"))
}

fn extract_package_name(input: &str) -> String {
    let error_prefix = "error:";
    let colon = ':';

    if let Some(error_idx) = input.find(error_prefix) {
        let remaining_text = &input[error_idx + error_prefix.len()..];
        if let Some(colon_idx) = remaining_text.find(colon) {
            let package_name = &remaining_text[..colon_idx].trim();
            return package_name.to_string();
        }
    }
    String::new() // Return an empty string if package name is not found
}

fn get_repository_name(package_name: &str) -> String {
    // Run the `pacman -Si` command and capture its output
    let output = Command::new("pacman")
        .arg("-Si")
        .arg(package_name)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Convert the stdout bytes to a string
            let stdout = String::from_utf8(output.stdout);
            match stdout {
                Ok(stdout) => {
                    // Find the "Repository" field in the output
                    if let Some(repository_line) = stdout.lines().find(|line| line.starts_with("Repository")) {
                        // Split the line by ':' and extract the repository name
                        let parts: Vec<&str> = repository_line.split(':').collect();
                        if parts.len() >= 2 {
                            return parts[1].trim().to_string();
                        }
                    }
                }
                Err(_) => eprintln!("Failed to convert stdout to string"),
            }
        }
        Ok(_) => eprintln!("Package not found"),
        Err(_) => eprintln!("Failed to execute command"),
    }

    // Return an empty string if an error occurred
    String::new()
}