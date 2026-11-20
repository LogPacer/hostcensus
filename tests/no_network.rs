//! The guards that keep network-capable code out of the build.
//!
//! This reads the policy files instead of driving the binary: the claim is
//! about what the build may contain, which no run of the binary can show.

use std::path::Path;

fn tracked(file: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap()
}

const BANNED_CRATES: [&str; 9] = [
    "reqwest",
    "rustls",
    "native-tls",
    "openssl",
    "openssl-sys",
    "hyper-rustls",
    "hyper-tls",
    "kube",
    "kube-client",
];

const REFUSED_SOCKET_TYPES: [&str; 6] = [
    "std::net::TcpStream",
    "std::net::TcpListener",
    "std::net::UdpSocket",
    "tokio::net::TcpStream",
    "tokio::net::TcpListener",
    "tokio::net::UdpSocket",
];

/// intent: example build_refuses_network_code exemplifies the_build_refuses_network_capable_code on cli
#[test]
fn the_policy_bans_network_crates_and_socket_types_and_the_lockfile_has_none() {
    let deny = tracked("deny.toml");
    for name in BANNED_CRATES {
        assert!(
            deny.contains(&format!("{{ crate = \"{name}\"")),
            "deny.toml does not ban {name}"
        );
    }

    let clippy = tracked("clippy.toml");
    for socket_type in REFUSED_SOCKET_TYPES {
        assert!(
            clippy.contains(&format!("path = \"{socket_type}\"")),
            "clippy.toml does not refuse {socket_type}"
        );
    }

    let manifest = tracked("Cargo.toml");
    assert!(
        manifest.contains(
            r#"bollard = { version = "0.21", default-features = false, features = ["pipe"] }"#
        ),
        "the engine client is not built with its local transport only"
    );

    let lockfile = tracked("Cargo.lock");
    for name in BANNED_CRATES {
        assert!(
            !lockfile.contains(&format!("name = \"{name}\"\n")),
            "Cargo.lock holds {name}"
        );
    }
}
