# Genesis of the public testnet

`genesis-vearl-testnet-1.json` is the genesis file of the network **vearl-testnet-1** (the one every release since rc24 and https://vearl.org/genesis.json serve):

- file SHA-256: `aee719a72d029584a7b2fe9c8a2d68019c749409ffa52632fd63b7551fe5ce07`
- genesis hash (what nodes and `network.json` check): `a5771be72054adbfca6654cef5d4dbbcfb350655c3e901bfa2f5e626ada4b744`
- start: 2026-10-23 16:00:00 UTC, faucet 1,000,000 VRL

It replaces the file that earlier release candidates carried (hash `46c57f50...`, used by the closed tests before the launch): the new genesis has the same parameters
plus a 1-unit allocation to a random address, kept secret until the launch instant, so that nobody could prepare blocks of the network in advance (a block commits to
the accounts of the genesis). `make-genesis.sh` shows how a genesis is produced.
