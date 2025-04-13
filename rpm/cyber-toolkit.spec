Name:           cyber-toolkit
Version:        21
Release:        1.ge20d83b%{?dist}
Summary:        Set your Cyber Security role

License:        MIT
URL:            https://github.com/Athena-OS/cyber-toolkit
Source0:        https://github.com/Athena-OS/cyber-toolkit/archive/refs/heads/main.tar.gz#/cyber-toolkit-main.tar.gz

BuildRequires:  cargo

ExclusiveArch:  x86_64 aarch64

%description
Cyber Toolkit is a CLI utility for Athena OS that allows you to define and switch between cybersecurity-oriented system roles.

%prep
%autosetup -n %{name}-main

%build
cargo build --release --locked

%install
install -Dm 755 target/release/%{name} %{buildroot}/usr/bin/%{name}
install -Dm 644 README.md %{buildroot}/usr/share/doc/%{name}/README.md
install -Dm 644 LICENSE %{buildroot}/usr/share/licenses/%{name}/LICENSE

%files
%license usr/share/licenses/%{name}/LICENSE
%doc usr/share/doc/%{name}/README.md
/usr/bin/%{name}

%changelog