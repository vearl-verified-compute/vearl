//! Signature of the auto-update manifest (`latest.json`) read by `vearl-miner` at every start.
//!
//! A hash written in the same file as the download address proves nothing if the server that holds both is compromised: whoever replaces the file
//! replaces the hash too, and every miner would run the new program. Each platform entry of the manifest therefore carries an Ed25519 signature
//! (`sig`, 128 hexadecimal digits) of `message(tag, platform, url, sha256)`; the public key is fixed in the miner at build time
//! (`VEARL_UPDATE_PUBKEY`), the private key never leaves the maintainer's machine (`vearl-release-sign`).
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// The exact text that is signed: it binds the release tag, the platform entry that is used, the download address and the SHA-256 of the program.
pub fn message(tag: &str, platform: &str, url: &str, sha256: &str) -> String {
    format!("vearl-update/1|{tag}|{platform}|{url}|{}", sha256.to_ascii_lowercase())
}

fn hex_to<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != 2 * N || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// True when `sig_hex` is a valid signature of `msg` by the key `pubkey_hex` (64 hexadecimal digits). Anything malformed is simply "false".
pub fn verify(pubkey_hex: &str, msg: &str, sig_hex: &str) -> bool {
    let (Some(pk), Some(sg)) = (hex_to::<32>(pubkey_hex), hex_to::<64>(sig_hex)) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(msg.as_bytes(), &Signature::from_bytes(&sg)).is_ok()
}

/// Signature (hex) of `msg` by the private seed `seed_hex` (64 hexadecimal digits).
pub fn sign(seed_hex: &str, msg: &str) -> Result<String, String> {
    let seed = hex_to::<32>(seed_hex.trim()).ok_or("the signing key must be 64 hexadecimal digits")?;
    Ok(to_hex(&SigningKey::from_bytes(&seed).sign(msg.as_bytes()).to_bytes()))
}

/// Public key (hex) of the private seed `seed_hex`.
pub fn public_key(seed_hex: &str) -> Result<String, String> {
    let seed = hex_to::<32>(seed_hex.trim()).ok_or("the signing key must be 64 hexadecimal digits")?;
    Ok(to_hex(SigningKey::from_bytes(&seed).verifying_key().as_bytes()))
}

/// The numbers inside a release tag ("rc25" -> [25], "v0.2.1" -> [0, 2, 1]), for the "strictly newer" rule.
fn numbers(tag: &str) -> Vec<u64> {
    tag.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect()
}

/// True only when `candidate` is strictly newer than `current`: a validly signed OLD manifest replayed by an attacker must not downgrade a miner.
/// A tag without any number is never newer.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (c, k) = (numbers(candidate), numbers(current));
    !c.is_empty() && c > k
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SHA: &str = "99b2b8b79869cd823c8f891dba02fcf6bd1903d459b421d9c8ecb428d3fd01e6";

    #[test]
    fn a_signed_entry_verifies_and_every_field_is_bound() {
        let pk = public_key(SEED).unwrap();
        let m = message("rc26", "win64", "https://vearl.org/release/VearlMiner.exe", SHA);
        let sg = sign(SEED, &m).unwrap();
        assert!(verify(&pk, &m, &sg));
        for bad in [
            message("rc27", "win64", "https://vearl.org/release/VearlMiner.exe", SHA),
            message("rc26", "linux64", "https://vearl.org/release/VearlMiner.exe", SHA),
            message("rc26", "win64", "https://evil.example/VearlMiner.exe", SHA),
            message("rc26", "win64", "https://vearl.org/release/VearlMiner.exe", &SHA.replace('9', "8")),
        ] {
            assert!(!verify(&pk, &bad, &sg), "{bad}");
        }
        assert_eq!(message("rc26", "win64", "u", "AB"), message("rc26", "win64", "u", "ab"), "the hash is compared in lower case");
    }

    #[test]
    fn another_key_a_tampered_signature_and_malformed_input_are_refused() {
        let pk = public_key(SEED).unwrap();
        let other = public_key(&"02".repeat(32)).unwrap();
        let m = message("rc26", "win64", "https://vearl.org/x", SHA);
        let sg = sign(SEED, &m).unwrap();
        assert!(!verify(&other, &m, &sg));
        let mut t = sg.clone().into_bytes();
        t[0] = if t[0] == b'0' { b'1' } else { b'0' };
        assert!(!verify(&pk, &m, &String::from_utf8(t).unwrap()));
        assert!(!verify(&pk, &m, ""));
        assert!(!verify(&pk, &m, &sg[..127]));
        assert!(!verify("zz", &m, &sg));
        assert!(!verify(&"00".repeat(32), &m, &sg));
        assert!(sign("abc", &m).is_err());
    }

    #[test]
    fn only_a_strictly_newer_tag_updates() {
        assert!(is_newer("rc26", "rc25"));
        assert!(is_newer("rc100", "rc99"));
        assert!(!is_newer("v0.2.0", "rc25"), "a change of tag format needs a new launcher, never an automatic update");
        assert!(!is_newer("rc25", "rc25"));
        assert!(!is_newer("rc24", "rc25"), "a replayed old manifest is not an update");
        assert!(!is_newer("latest", "rc25"));
        assert!(is_newer("v0.1.1", "v0.1.0"));
        assert!(!is_newer("v0.1.0", "v0.1.1"));
    }
}
