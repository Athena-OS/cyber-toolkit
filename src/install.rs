use crate::utils::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, stdin, BufRead, BufReader, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

// -------------- PAYLOAD SECTION --------------
pub fn getpayloads() -> Result<(), i32> {
    // Note: install() signature includes role name and path so errors can mention them
    install(
        PackageManager::Pacman,
        &[
            "fuzzdb",
            "payloadsallthethings",
            "seclists",
        ],
        "payloads",
        "/usr/share/cyber-toolkit/roles/payloads.role",
    )?;

    let target_file = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt";
    let tar_file = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz";

    if fs::metadata(target_file).is_err() {
        println!("Extracting rockyou.txt...");
        let status = Command::new("tar")
            .arg("-zxvf")
            .arg(tar_file)
            .arg("-C")
            .arg("/usr/share/seclists/Passwords/Leaked-Databases")
            .status()
            .expect("Failed to execute tar command");

        if status.success() {
            println!("rockyou.txt extracted successfully!");
        } else {
            eprintln!("Failed to extract rockyou.txt");
            return Err(-1);
        }
    } else {
        println!("rockyou.txt found!");
    }

    let paysource = vec![
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
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

// -------------- INSTALL MAIN FUNCTION --------------
pub fn install(
    pkgmanager: PackageManager,
    pkgs: &[&str],
    role_arg: &str,   // role name shown in the hint (e.g. "blue")
    role_path: &str,  // full path to the .role file used
) -> Result<(), i32> {
    let retry = Arc::new(Mutex::new(true));
    let mut retry_counter = 0;

    while *retry.lock().unwrap() && retry_counter < 15 {
        // reset retry flag for this loop
        {
            let mut r = retry.lock().unwrap();
            *r = false;
        }

        let retry_clone = Arc::clone(&retry);
        let mut pkgmanager_name = String::new();
        let mut child_result: Option<std::process::Child> = None;

        // spawn the chosen package manager
        match pkgmanager {
            PackageManager::Dnf => {
                Command::new("dnf")
                    .arg("makecache")
                    .arg("--refresh")
                    .status()
                    .expect("Failed to refresh dnf cache");
                let child = Command::new("dnf")
                    .arg("install")
                    .arg("-y")
                    .args(pkgs)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("Failed to start dnf");
                child_result = Some(child);
                pkgmanager_name = String::from("dnf");
            }
            PackageManager::OSTree => {
                Command::new("rpm-ostree")
                    .arg("refresh-md")
                    .status()
                    .expect("Failed to refresh rpm-ostree cache");
                let child = Command::new("rpm-ostree")
                    .arg("install")
                    .args(pkgs)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("Failed to start rpm-ostree");
                child_result = Some(child);
                pkgmanager_name = String::from("rpm-ostree");
            }
            PackageManager::Pacman => {
                let child = Command::new("pacman")
                    .arg("-Syyu")
                    .arg("--needed")
                    .arg("--noconfirm")
                    .args(pkgs)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("Failed to start pacman");
                child_result = Some(child);
                pkgmanager_name = String::from("pacman");
            }
            PackageManager::Pacstrap => {
                let child = Command::new("pacstrap")
                    .arg("/mnt")
                    .args(pkgs)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("Failed to start pacstrap");
                child_result = Some(child);
                pkgmanager_name = String::from("pacstrap");
            }
            PackageManager::None => {
                println!("No package manager selected");
            }
        }

        // if we didn't spawn anything, loop
        let mut child = match child_result {
            Some(c) => c,
            None => {
                retry_counter += 1;
                continue;
            }
        };

        // take stderr and start the reader thread BEFORE wait()
        let stderr = child.stderr.take().expect("piped stderr");
        let pkg_name_for_thread = pkgmanager_name.clone();

        let stderr_reader = thread::spawn(move || -> io::Result<Vec<String>> {
            let mut collected: Vec<String> = Vec::new();
            let reader = BufReader::new(stderr);

            for line_res in reader.lines() {
                let line = line_res?;
                collected.push(line.clone());

                // mirror/signature handling while streaming (no early returns)
                if pkg_name_for_thread == "pacman" || pkg_name_for_thread == "pacstrap" {
                    if line.contains("failed retrieving file") && line.contains("from") {
                        if let Some(mirror_name) = extract_mirror_name(&line)
                            && let Some(mirrorlist_file) = find_mirrorlist_file(&mirror_name) {
                                if let Err(err) = move_server_line(&mirrorlist_file, &mirror_name) {
                                    eprintln!(
                                        "Failed to move 'Server' line in {mirrorlist_file}: {err}"
                                    );
                                } else {
                                    let mut retry = retry_clone.lock().unwrap();
                                    *retry = true;
                                    println!("Detected unstable mirror: {mirror_name}. Retrying by a new one...");
                                }
                            }
                    } else if line.contains("signature from") && line.contains("is invalid") {
                        let extracted_name = extract_package_name(&line);
                        let mut mirrorlist_filename = String::new();

                        if extracted_name == "blackarch" {
                            mirrorlist_filename =
                                String::from("/etc/pacman.d/blackarch-mirrorlist");
                        } else {
                            let repository = get_repository_name(&extracted_name);
                            println!(
                                "Package {extracted_name} found in repository: {repository}"
                            );

                            if ["core", "extra", "community", "multilib"]
                                .contains(&repository.as_str())
                            {
                                mirrorlist_filename = String::from("/etc/pacman.d/mirrorlist");
                            }
                            if repository == "blackarch" {
                                mirrorlist_filename =
                                    String::from("/etc/pacman.d/blackarch-mirrorlist");
                            }
                            if repository == "chaotic-aur" {
                                mirrorlist_filename =
                                    String::from("/etc/pacman.d/chaotic-mirrorlist");
                            }
                        }

                        if !mirrorlist_filename.is_empty() {
                            match get_first_mirror_name(&mirrorlist_filename) {
                                Ok(mirror_name) => {
                                    println!("Mirror Name: {mirror_name}");
                                    if let Err(err) =
                                        move_server_line(&mirrorlist_filename, &mirror_name)
                                    {
                                        println!(
                                            "Failed to move 'Server' line in {mirrorlist_filename}: {err}"
                                        );
                                    } else {
                                        let mut retry = retry_clone.lock().unwrap();
                                        *retry = true;
                                        println!("Detected invalid signature key in mirror: {mirror_name}. Retrying by a new one...");
                                    }
                                }
                                Err(err) => eprintln!("Error: {err}"),
                            }
                        }
                    }
                }
            }

            Ok(collected)
        });

        // wait for the child AFTER reader started
        let exit_status = child.wait().expect("Failed to wait for package manager");

        // join reader thread and get all stderr lines
        let stderr_lines: Vec<String> = match stderr_reader.join() {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                eprintln!("Error while reading stderr: {e}");
                Vec::new()
            }
            Err(_) => {
                eprintln!("stderr thread panicked");
                Vec::new()
            }
        };

        // print stderr lines with label depending on success
        let exit_code = exit_status.code().unwrap_or(-1);
        for l in &stderr_lines {
            if exit_status.success() {
                println!("{pkgmanager_name} warn (exit code {exit_code}): {l}");
            } else {
                eprintln!("{pkgmanager_name} err (exit code {exit_code}): {l}");
            }
        }

        // if failed, print failure line and the friendly hint LAST, then return
        if !exit_status.success() {
            println!("The package manager failed with exit code: {}", exit_code);

            // find the last "target not found" line (if any) and print the hint at the very end
            if let Some(not_found_line) = stderr_lines
                .iter()
                .rev()
                .find(|l| l.contains("error: target not found:"))
            {
                let mut pkgname = "";
                if let Some(last_part) = not_found_line.split(':').next_back() {
                    pkgname = last_part.trim();
                }

                // final hint printed at the end (red for error, yellow for hint)
                println!(
                    "\n\x1b[31m❌ {not_found_line}\x1b[0m\n\
                     \x1b[33m💡 Edit the related \"{role_arg}\" role file at {role_path}.role and remove \"{pkgname}\"\x1b[0m"
                );
            }

            return Err(exit_code);
        }

        retry_counter += 1;
    }

    Ok(())
}

// -------------- Helper functions --------------

fn extract_mirror_name(error_message: &str) -> Option<String> {
    let words: Vec<&str> = error_message.split_whitespace().collect();
    if let Some(from_index) = words.iter().position(|&w| w == "from")
        && let Some(mirror_name) = words.get(from_index + 1) {
            return Some(mirror_name.to_string());
        }
    None
}

fn find_mirrorlist_file(mirror_name: &str) -> Option<String> {
    let mirrorlist_paths = [
        "/etc/pacman.d/mirrorlist",
        "/etc/pacman.d/chaotic-mirrorlist",
        "/etc/pacman.d/blackarch-mirrorlist",
    ];

    for &mirrorlist_path in &mirrorlist_paths {
        if let Ok(content) = fs::read_to_string(mirrorlist_path)
            && content.contains(mirror_name) {
                return Some(mirrorlist_path.to_string());
            }
    }
    None
}

fn move_server_line(mirrorlist_path: &str, mirror_name: &str) -> io::Result<()> {
    let mut lines: Vec<String> = Vec::new();
    let file = File::open(mirrorlist_path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        lines.push(line?);
    }

    // Find the last "Server" line and move the URL line to the end
    let last_server_index = lines.iter().rposition(|line| line.trim().starts_with("Server"));
    if let Some(last_server_index) = last_server_index
        && let Some(mirror_url_index) = lines.iter().position(|line| line.contains(mirror_name)) {
            let mirror_url_line = lines.remove(mirror_url_index);
            let insert_index = last_server_index;
            lines.insert(insert_index, mirror_url_line.clone());

            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(mirrorlist_path)?;
            for line in lines {
                writeln!(file, "{line}")?;
            }
            println!("'{mirror_url_line}' moved at the end of {mirrorlist_path}");
        }
    Ok(())
}

pub fn uninstall(pkgmanager: PackageManager, rolepkg: Vec<Vec<String>>) {
    println!("Do you want to remove tools of your previous roles (y/n)?");

    let mut answer = String::new();
    stdin().read_line(&mut answer).expect("Failed to read input");

    if answer.trim().eq_ignore_ascii_case("y") {
        println!("Uninstalling any previous role tools...\n");

        for role in rolepkg {
            for pkg in role {
                if is_package_installed(&pkgmanager, &pkg) {
                    println!("Uninstalling package: {pkg}");
                    if uninstall_packages(&pkgmanager, vec![pkg.clone()]) {
                        println!("Successfully uninstalled: {pkg}");
                    } else {
                        eprintln!("Failed to uninstall: {pkg}");
                    }
                }
            }
        }
    } else {
        println!("Skipping uninstallation.");
    }
}

fn is_package_installed(pkgmanager: &PackageManager, package_name: &str) -> bool {
    let status: ExitStatus = match pkgmanager {
        PackageManager::Dnf | PackageManager::OSTree => {
            Command::new("rpm")
                .arg("-q")
                .arg(package_name)
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .expect("Failed to execute rpm -q")
        }
        PackageManager::Pacman => {
            Command::new("pacman")
                .arg("-Qq")
                .arg(package_name)
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .expect("Failed to execute pacman -Qq")
        }
        _ => {
            eprintln!("Unsupported package manager for checking installed packages.");
            return false;
        }
    };

    status.success()
}

fn uninstall_packages(pkgmanager: &PackageManager, pkgs: Vec<String>) -> bool {
    for package in pkgs {
        let status: ExitStatus = match pkgmanager {
            PackageManager::Dnf => Command::new("dnf")
                .arg("remove")
                .arg("-y")
                .arg(&package)
                .status()
                .expect("Failed to execute dnf uninstall"),
            PackageManager::OSTree => Command::new("rpm-ostree")
                .arg("uninstall")
                .arg(&package)
                .status()
                .expect("Failed to execute rpm-ostree uninstall"),
            PackageManager::Pacman => Command::new("pacman")
                .arg("-Rns")
                .arg("--noconfirm")
                .arg(&package)
                .status()
                .expect("Failed to execute pacman uninstall"),
            _ => {
                eprintln!("Unsupported package manager for uninstall.");
                return false;
            }
        };

        if !status.success() {
            eprintln!("Failed to uninstall package: {package}");
            return false;
        }
    }
    true
}

fn get_first_mirror_name(filename: &str) -> Result<String, io::Error> {
    let file = File::open(filename)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if let Some(eq) = line.find('=')
            && line[..eq].trim() == "Server" {
                return Ok(line[eq + 1..].trim().to_string());
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
            return remaining_text[..colon_idx].trim().to_string();
        }
    }
    String::new()
}

fn get_repository_name(package_name: &str) -> String {
    let output = Command::new("pacman").arg("-Si").arg(package_name).output();
    match output {
        Ok(output) if output.status.success() => {
            if let Ok(stdout) = String::from_utf8(output.stdout)
                && let Some(line) = stdout.lines().find(|l| l.starts_with("Repository")) {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        return parts[1].trim().to_string();
                    }
                }
        }
        Ok(_) => eprintln!("Package not found"),
        Err(_) => eprintln!("Failed to execute command"),
    }
    String::new()
}
