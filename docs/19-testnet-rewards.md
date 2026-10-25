# 19 - Testnet contributors program

> **Status: a commitment of the team.** The team commits to thank the people who help secure the public testnets by allocating tokens of the
> mainnet to them, under the rules of this document: **7 % of the maximum mainnet supply** for the contributors of five public testnets,
> **0.7 %** for the first one. What is **not** promised: a mainnet date, or any price or value of the tokens. Testnet tokens themselves have no
> value, are not for sale and cannot be converted. Nothing here is investment advice. The rules can change only before they apply, and never
> reduce points already earned (section 8).

## 1. What is rewarded

Real, verifiable contribution to the testnet: blocks that your address mined on the public chain, counted from the blocks themselves.
Mining Quantus with the optional add-on does not count; running the miner without finding blocks is not measured.

## 2. The reward pool

The team sets aside a fixed share of the mainnet supply for the testnet contributors. Planned size: **7 % of the maximum mainnet supply**, shared
by **five public testnets**, with a larger part for the later ones (0.7 %, 1.05 %, 1.4 %, 1.75 % and 2.1 %). The public testnet that opens on
23 October 2026 is the first: its pool is **0.7 % of the maximum supply**, shared between its eligible addresses in proportion to their
points (section 3). The team commits to these shares. With the maximum supply planned for the mainnet, 56,064,000 VRL (docs/04 section 4), this pool is
392,448 VRL. The durations in this document (early period, active days) are counted in days because a testnet is short; if the schedule changes, the team announces the new values before they
apply. The mainnet comes after the last of the public testnets. The size of a pool does not depend on how many people take part.

## 3. How points are counted

Every number is computed from the blocks of the chain, by `vearl-core/tools/testnet_rewards.py`. Parameters (they are printed in every
result):

| rule | value |
|---|---|
| a valid block mined to your address | 1 point |
| a block that carried **paid work** (a job from a client) | 1.5 points, with three limits: not for a job the miner submitted itself (its own client), at most 20 blocks of one job, and the same operation, layer or product of a job only once. Such a block is a valid block and counts 1 point |
| early period: the first 3 days after the start | points ×1.25 |
| scoring periods | days, for the daily leaderboard; the final score is the sum |

If the team finds that the start of the chain was gamed (for example blocks mined in advance and released at the launch), it may leave the first minutes out of the score (`--grace-minutes`) and will say so publicly.

The leaderboard (<https://vearl.org/leaderboard/>) is refreshed regularly. It is built from the public files `leaderboard.json`,
`leaderboard.csv` and `blocks.json` (the blocks used, with their SHA-256): you can download the blocks and re-run the same script to get
the same result, bit for bit.

Why blocks: a block carries the address of the miner who found it, and nobody can find a block without really doing the work, so the number of
blocks is proportional to the real computing power and cannot be inflated off-chain. A person who splits one machine over several addresses
gets the same total points, so there is nothing to gain by creating many addresses.

Not counted in this first version: a bonus for completed jobs (a worker can create jobs for itself with free testnet tokens, so a bonus would need
a safe way to ignore self-dealing). It may be added later; the rules in force are always the ones in this file.

## 3 bis. Mining in a pool

Blocks that a pool finds carry the pool's key, not your address, so the pool is not paid points itself: the points of a registered pool's blocks
are **shared between its miners in proportion to their verified work** (share weight) in the scoring day, computed from the signed hourly ledger
that the pool publishes (docs/16 section 13). Rules:

- Only pools **registered with the team** count (write to contact@vearl.org with the pool address and the URL of its ledger). The address of a registered pool
  is not a participant. A pool that is not registered earns nothing for its miners; an operator who runs one and registers its address as a
  participant to keep the points breaks section 4 (honest behavior, one participant per person) and is excluded when found, which the manual review of
  the top of the ranking (section 6) is there to do.
- Only miners that speak `vpool/2` take part: they receive signed receipts of their work, which they can use to prove what the pool owes them
  (`vearl-pool-audit`). Their address must be registered like any other (section 5) and meets the same conditions (section 4); an active day is a
  day in which they had work in the pool.
- The team audits every registered pool with `vearl-pool-audit` against the chain (`audit.json`, published). An hour found **fraudulent** counts for
  nothing and the pool is excluded; an hour found **suspect** is held until a person has looked at it; an hour that has not been audited yet is held.
- Jobs are not shared: a paid job is computed by a worker with its own key (`node --worker`), and its rewards are that worker's alone.
- If you mine in a pool and also on your own, the points add up. The pool changes nothing to what you can earn per unit of work.
- To see your points, type your payout address on the pool's page: it shows the points you have earned through that pool (provisional, computed by the pool
  from its signed ledger) and, if the pool displays it, your row of the official leaderboard. The official figure is the one that counts.

How the team runs it: `/etc/vearl/rewards-pools.json` lists the registered pools (`address`, `name`, `url` of the pool's statistics server, and where to keep
its documents and report, for example `/var/www/vearl-rewards/pools/NAME` and `/var/www/vearl-rewards/pools/NAME-audit.json`). Every hour
`vearl-rewards.sh` runs `tools/audit_pools.py` (download of the documents, random shares, `vearl-pool-audit` against the blocks of the previous run)
and then the leaderboard with `--pools`. The documents and the reports are published next to the leaderboard under `/rewards/pools/`, so that anybody
can re-run the computation: `python3 tools/testnet_rewards.py --blocks-file blocks.json --pools pools.json ...` gives the same result.

## 4. Who is eligible

All of the following:

1. **Activity:** at least **3 distinct active days** (24-hour windows since the start of the testnet in which you mined at least one block).
2. **Minimum share:** at least **0.005 %** of all the points, to avoid dust.
3. **Registered address:** you registered the address, with a signature that proves that you own it (section 5), before the deadline
   announced by the team.
4. **The development fee is paid.** Mining Quantus with the optional add-on is allowed and does not count for the rewards, but it comes with a
   development fee of 10 % of the Quantus mining time (docs/15 and docs/17). An address whose miner uses the add-on with the fee removed, reduced or
   redirected (a modified or unofficial build, detected by the audit of docs/17) is not eligible. The counts of compliant and non-compliant miners
   are published at <https://vearl.org/rewards/fee-stats.json>. A miner that does not use the add-on has no fee and is not concerned.
5. **Honest behavior:** no fraud (a worker proven to have published a wrong result, a manipulated block, a forged registration), and no attack on
   the network or on other participants outside the rules of `SECURITY.md`. Responsible reports of weaknesses are welcome and are rewarded
   separately.
6. **One participant per person.** You may use several machines, but not several identities to receive more than your share. Addresses that
   look like one person's are reviewed by hand.
7. **Legal conditions:** you are of legal age in your country, you are not in a country or on a list that the team has to exclude by law
   (the list is published before the final snapshot; registering earlier does not guarantee eligibility), and you accept these terms.

The team may exclude an address or a pool that breaks these rules, and publishes the address and the reason.

## 5. How to register

Registration is done by e-mail, but you do not have to write the e-mail yourself: the wallet sends it. With the wallet window (`vearl-wallet-gui`, docs/20) it is the **Rewards** page: type your contact, press *Sign the registration*, check the three lines, press *Send the registration*. The command line below does the same.

1. Mine with an address of your wallet (the one the miner created, or `vearl-wallet new`).
2. In the folder of the wallet, run (replace the contact with your Discord name or an e-mail address):

   ```
   vearl-wallet register --file wallet.json --contact "YOUR_DISCORD_NAME_OR_EMAIL"
   ```

   The wallet asks your password, signs the registration message
   `Vearl testnet rewards registration. Address: ADDRESS. Contact: CONTACT. I accept the terms in docs/19.`, **shows you the three lines**
   (address, message, signature) and asks you to confirm before it sends **one** e-mail from `registrar@vearl.org` to `register@vearl.org`.
   Nothing secret is sent: a signature proves that you own the address without revealing any key. Nobody will ever ask for your 24 words, your
   password or your wallet file.
3. A script on the server reads that mailbox every two minutes, checks the signature and publishes the list of registered addresses (addresses
   only, never the contacts) at <https://vearl.org/rewards/registered.json>. Your address should appear there within a few minutes. The
   leaderboard marks only registered addresses as eligible.
4. If sending fails (some networks block outgoing mail), the wallet says why and shows the three lines: send them yourself in an e-mail to
   `register@vearl.org` (subject: Vearl testnet registration). `vearl-wallet register --file wallet.json --contact "..." --print-only` prints
   them without sending anything. The old way still works too: `vearl-wallet sign --file wallet.json --message "..."`.
5. Anyone can check a registration with `vearl-wallet verify --address ADDRESS --message "..." --signature HEX`, and the team does it in bulk with
   `tools/process_registration_mail.py` (the script that reads the mailbox) and `tools/verify_registration.py`.

How it is protected: `registrar@vearl.org` is a send-only account whose password is public (it is in `vearl-core/src/regmail.rs`, because the
wallet needs it). The mail server lets it write to `register@vearl.org` only, on a dedicated port, with a small size and a rate limit, and it has
no mailbox. Nobody can register an address that they do not own: the script accepts a registration only if the signature is valid, whoever sent
the mail. A registration sent twice counts once; a contact that registers several addresses is reviewed by hand (one participant per person).

## 6. Snapshot, disputes and distribution

- A **final snapshot** is taken when the testnet ends: the team publishes the blocks, the script, the full leaderboard and the list of excluded
  addresses with reasons. There are **14 days** to contest a result before it becomes final.
- The top of the ranking is reviewed by hand before anything is paid.
- **Distribution at the mainnet launch**: the allocation is committed; its release is planned as a first part (25 %) at the launch, the rest (planned 75 %) spread over 6 to 12
  months, which rewards people who stay and avoids an immediate sell-off. The mainnet does not yet have an on-chain vesting mechanism: until it
  does, the later parts are released by the team in tranches, and the team will say which mechanism is used before the first payment.
- The leaderboard data is kept outside the chain, because the testnet can be reset; the published snapshot is what counts.

## 7. Personal data

Only what is needed: your wallet address, the contact you give at registration (kept private, never published), and what is public on the chain. The mail server sees the IP address that sends the registration, like any web server, and keeps its usual logs. The team does not collect
identity documents for this program, and may ask for more information later only if the law requires it. You can ask the team to delete your
contact details at any time (the on-chain data stays).

## 8. Changes and contact

The rules may change; changes are announced before they apply and never reduce points already earned for blocks mined before the
announcement. Questions and corrections: contact@vearl.org. Security reports: security@vearl.org.
