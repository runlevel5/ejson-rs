Name:           ejson
Version:        1.0.6
Release:        1%{?dist}
Summary:        Manage encrypted secrets using public key encryption

License:        MIT
URL:            https://github.com/runlevel5/ejson-rs
# Release CI attaches this tarball (and a matching .sha256) to the GitHub
# Release for the version tag. It already has `cargo vendor` run against it
# (see .github/workflows/release.yml), so we build fully offline against
# the vendored copy instead of using cargo-rpm-macros' usual "resolve
# against /usr/share/cargo/registry" mode (%%cargo_prep /
# %%cargo_generate_buildrequires). See .copr/Makefile.
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}-vendored.tar.xz

BuildRequires:  cargo
BuildRequires:  rust

%description
ejson is a Rust implementation of Shopify/ejson: a drop-in replacement for
the original Go tool that manages secrets in source control using
public-key cryptography. Legacy v1 keys use NaCl Box (Curve25519 +
XSalsa20 + Poly1305); hybrid post-quantum v2 keys combine X25519 with
ML-KEM-768 and encrypt values with XChaCha20-Poly1305. Public keys are
embedded in the secrets file; private keys are stored separately on the
filesystem. Supports JSON, YAML and TOML secret files.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --offline

%install
install -Dm755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

%check
cargo test --release --offline

%files
%license LICENSE.txt
%doc README.md
%{_bindir}/%{name}

%changelog
* Thu Jul 09 2026 Trung Lê <8@tle.id.au> - 1.0.6-1
- Update to 1.0.6.

* Wed Jul 08 2026 Trung Lê <8@tle.id.au> - 1.0.5-1
- Update to 1.0.5.

* Wed Jul 08 2026 Trung Lê <8@tle.id.au> - 1.0.3-1
- Initial package.
