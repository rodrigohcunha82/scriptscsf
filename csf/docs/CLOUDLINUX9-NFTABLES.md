# CSF Next — CloudLinux 9 + nftables architecture

Development target: CloudLinux 9.x with cPanel/WHM.

## Safety principles

1. nftables is the enforcement layer in the kernel.
2. SQLite is persistent state and audit history, not a runtime dependency for keeping an already-loaded firewall active.
3. A database failure must never trigger an automatic firewall flush.
4. Existing CSF commands and text lists remain import/export compatibility surfaces during migration.
5. Firewall changes must be validated before atomic ruleset application.
6. Development defaults to a testing/fail-safe mode until SSH, WHM, DNS, HTTP/S, Exim and Dovecot connectivity is verified.

## Layers

- CSF/LFD policy engine: decides allow, deny, temporary block and escalation.
- SQLite state store: addresses, active/historical blocks, events and allowlist.
- nftables backend: table inet csf, chains and native sets with timeout.
- compatibility layer: csf.allow, csf.deny, csf.ignore and familiar csf CLI commands.

## Initial nftables model

Use an inet family table so common policy can cover IPv4 and IPv6. Keep distinct IPv4/IPv6 address sets where datatype requires it. Temporary sets use native timeout; permanent sets do not.

The first implementation will generate and validate a complete candidate ruleset before changing the live ruleset. Rollback artifacts are mandatory.

## Database

Default path: /var/lib/csf/csf.db

SQLite is local-only, uses WAL, foreign keys and FULL synchronous mode. Database writes record security state; nftables remains responsible for packet enforcement.

Schema: db/schema-v1.sql.
