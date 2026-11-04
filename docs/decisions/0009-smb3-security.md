# ADR 0009 — Bounded SMB3 security profile

[简体中文](0009-smb3-security.zh-CN.md)

Accepted for the M6 backend preview, 2026-10-30.

Extend the existing SMB worker and shared file authority, independently negotiating 3.0, 3.0.2 and 3.1.1. Use OpenSSL EVP AES-CMAC, AES-128-CCM/GCM and SHA-512 plus HMAC-SHA256 counter-mode derivation; do not implement cipher primitives locally. The unchanged NTLMv2 exchange supplies the exported session key. Separate directional keys and exact transcript binding prevent cross-direction use and altered 3.1.1 negotiation. 3.0/3.0.2 retain signed negotiate validation.

Highest-common 3.1.1 is the modern default. Signed 2.1 compatibility remains available. Encryption is client-selected, so clients that require confidentiality must explicitly require it and constrain their minimum dialect. The service advertises only the algorithm/capability subset implemented and tested. GMAC, AES-256, compression and additional transports are deferred.

Validate the whole transform and all compound headers/signatures before file operations. Use the credit MessageId window for replay rejection, a bounded nonce set for received nonce reuse, and random-prefix/counter outbound nonces. Close after 65,536 encrypted frames per direction to bound memory; automatic rekey is deferred. Connections cannot bind additional sessions/channels. Errors in authentication/secure negotiation close the connection and stop later compound commands.

Caching, notification, durable/persistent handles and multichannel are independent features. Grant none; explicitly reject durable reconnect, notification and binding. This preserves immediate shared-authority consistency and honest restart semantics: authenticate again and reopen, with committed delete intents recovered by the file authority. The [M6 guide](../m6.md) and [evidence](../evidence/m6/README.md) define the selected profile; the broader native-client/Samba release gate remains open.

### 2026-11-04

The Full SMB/NFS expansion now implements AES-256-CCM/GCM for SMB 3.1.1, including full Kerberos authentication-key derivation; see [M6](../m6.md). The earlier AES-256 exclusion describes the original bounded profile, not the current implementation. GMAC and transport extensions remain open.

## Full-compatibility extension — 2026-11-04 notifications

The expanded user goal supersedes the earlier notification rejection: CHANGE_NOTIFY now has native directory streams, shared metadata events and signed/encrypted asynchronous completion. Caching, durable handles and multichannel remain separate unfinished work. [Notification implementation and evidence](../smb-notifications.md) records bounds, passing independent/upstream lifecycle cases and the still-failing full Samba diagnostic. This extension does not close the full SMB release gate.

## Full-compatibility extension — 2026-11-04 signing

The expanded implementation now negotiates GMAC, CMAC and HMAC-SHA256 for SMB 3.1.1. Missing or non-overlapping signing offers select the mandatory CMAC fallback. Independent primitive, signed client, nonce separation, cancellation and Kerberos checks pass locally under Clang ASan/UBSan. Remote acceptance is pending; encryption negotiation without a common cipher and other full-compatibility gates remain open.
