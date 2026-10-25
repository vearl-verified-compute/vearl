//! vearl-release-sign: the maintainer's tool for the signature of the auto-update manifest (`latest.json`, see src/updatesig.rs).
//!
//!   vearl-release-sign keygen KEYFILE              creates the private signing key (refuses to overwrite) and prints the PUBLIC key
//!   vearl-release-sign pubkey KEYFILE              prints the public key of a signing key
//!   vearl-release-sign sign KEYFILE latest.json    signs the "win64", "linux64" and "hiveos" entries (adds "sig") and rewrites the file
//!   vearl-release-sign verify PUBKEY latest.json   checks every entry
//! Keep KEYFILE OFF the repository and OFF every server: whoever holds it can make every miner run any program.
use rand::RngCore;
use serde_json::Value;
use vearl_core::updatesig::{message, public_key, sign, verify};

const PLATFORMS: [&str; 3] = ["win64", "linux64", "hiveos"];

fn die(m: &str) -> ! {
    eprintln!("error: {m}");
    std::process::exit(1)
}

fn entry_fields(v: &Value, platform: &str) -> Option<(String, String, String)> {
    let tag = v["tag"].as_str()?.to_string();
    let url = v[platform]["url"].as_str()?.to_string();
    let sha = v[platform]["sha256"].as_str()?.to_string();
    if !url.starts_with("https://") || sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        die(&format!("{platform}: the url must be https:// and sha256 64 hexadecimal digits"));
    }
    Some((tag, url, sha))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_else(|e| die(&format!("{p}: {e}")));
    match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", keyfile] => {
            if std::path::Path::new(keyfile).exists() {
                die("the key file already exists: refusing to overwrite a signing key");
            }
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
            std::fs::write(keyfile, format!("{hex}\n")).unwrap_or_else(|e| die(&format!("{keyfile}: {e}")));
            println!("signing key written to {keyfile} (keep it private and backed up)");
            println!("PUBLIC key (VEARL_UPDATE_PUBKEY at build time): {}", public_key(&hex).unwrap());
        }
        ["pubkey", keyfile] => println!("{}", public_key(&read(keyfile)).unwrap_or_else(|e| die(&e))),
        ["sign", keyfile, manifest] => {
            let seed = read(keyfile);
            let mut v: Value = serde_json::from_str(&read(manifest)).unwrap_or_else(|e| die(&format!("{manifest}: {e}")));
            let mut n = 0;
            for p in PLATFORMS {
                if let Some((tag, url, sha)) = entry_fields(&v, p) {
                    let sig = sign(&seed, &message(&tag, p, &url, &sha)).unwrap_or_else(|e| die(&e));
                    v[p]["sig"] = Value::String(sig);
                    n += 1;
                }
            }
            if n == 0 {
                die("no platform entry (win64, linux64, hiveos) with url and sha256 in the manifest");
            }
            std::fs::write(manifest, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap_or_else(|e| die(&format!("{manifest}: {e}")));
            println!("{n} entr{} signed in {manifest}", if n == 1 { "y" } else { "ies" });
        }
        ["verify", pubkey, manifest] => {
            let v: Value = serde_json::from_str(&read(manifest)).unwrap_or_else(|e| die(&format!("{manifest}: {e}")));
            let (mut ok, mut bad) = (0, 0);
            for p in PLATFORMS {
                if let Some((tag, url, sha)) = entry_fields(&v, p) {
                    if verify(pubkey, &message(&tag, p, &url, &sha), v[p]["sig"].as_str().unwrap_or("")) {
                        ok += 1;
                        println!("{p}: signature OK");
                    } else {
                        bad += 1;
                        println!("{p}: signature MISSING or INVALID");
                    }
                }
            }
            if bad > 0 || ok == 0 {
                std::process::exit(2);
            }
        }
        _ => die("usage: vearl-release-sign keygen KEYFILE | pubkey KEYFILE | sign KEYFILE latest.json | verify PUBKEY latest.json"),
    }
}
