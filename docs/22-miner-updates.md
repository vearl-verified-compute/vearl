# 22. Miner updates (rc25)

`vearl-miner` can run a newer release without any installation. This page says exactly what it does, what protects it, and how a release is published.

## What the miner does at each start

1. It downloads `https://vearl.org/release/latest.json` (at most 5 seconds; nothing is printed when offline or when there is no update).
2. It keeps the entry of its platform (`win64`, `linux64`; HiveOS uses `hiveos` and falls back to `linux64`) only if **all** of this holds:
   - the tag is **strictly newer** than the miner's own (`rc26` > `rc25`; numbers are compared, so a validly signed *old* manifest replayed by someone is not an update, and a tag without a number is never newer);
   - the address is `https://` and the SHA-256 has 64 hexadecimal digits;
   - the entry's `sig` is a valid Ed25519 signature, by the **release key built into the miner**, of
     `vearl-update/1|<tag>|<platform entry>|<url>|<sha256 in lower case>`.
3. It downloads the program to the temporary folder, checks the SHA-256, runs it **in the same window** (with the miner's own arguments) and deletes it when it ends. Nothing is installed: the files of the miner's folder never change, and closing the miner removes the update.
4. If a newer release is announced but the signature is missing or wrong, it prints one line (`its manifest is not signed by the Vearl release key: ignored`) and goes on with the program it is.

`--no-update` skips the whole check; `--devnet` never checks. A build made without `VEARL_UPDATE_PUBKEY` (every development build) never updates itself.

## Why a signature

The SHA-256 of the program sits in the same file as its address. Whoever controls the web server (a stolen password, a hosting incident) can replace both, and every miner that starts would run the new program with the user's rights. With the signature, the server only *carries* the manifest: a program the maintainer did not sign is refused, and the private key is never on a server.

What it does **not** protect against: someone who holds the private key, a compromise of the machine that builds and signs the release, or a miner whose own executable was replaced before it ran. The release key therefore lives only on the maintainer's computer, with a backup.

## `latest.json`

```json
{
  "tag": "rc26",
  "win64":   { "url": "https://vearl.org/release/...", "sha256": "…64 hex…", "sig": "…128 hex…" },
  "linux64": { "url": "https://vearl.org/release/...", "sha256": "…",         "sig": "…" },
  "hiveos":  { "url": "https://vearl.org/release/...", "sha256": "…",         "sig": "…" }
}
```

## Publishing a release (maintainer)

```
vearl-release-sign keygen KEYFILE              once; prints the PUBLIC key, which is given to every build as VEARL_UPDATE_PUBKEY
vearl-release-sign sign KEYFILE latest.json    after writing tag/url/sha256 of each platform: adds the "sig" fields
vearl-release-sign verify PUBKEY latest.json   checks every entry (exit status 2 if one is wrong or missing)
```

1. Build and upload the new programs; put their address and SHA-256 in `latest.json` with the **new tag**, which must be greater than the tag of the miners you want to reach.
2. Sign it, verify it, then upload `latest.json` last (miners read it as soon as it is there).
3. To withdraw an update, delete `latest.json` (a miner then simply finds nothing).

The private key stays off the repository and off every server. If it is lost, miners keep working but cannot be updated this way: publish a new release by the usual download with a new key. If it leaks, publish such a release at once.
