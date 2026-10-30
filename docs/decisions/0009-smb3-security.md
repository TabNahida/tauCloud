# ADR 0009 — Bounded SMB3 security profile

[简体中文](0009-smb3-security.zh-CN.md)

Accepted for the M6 backend preview, 2026-10-30.

Extend the existing SMB worker and shared file authority, independently negotiating 3.0, 3.0.2 and 3.1.1. Use OpenSSL EVP AES-CMAC, AES-128-CCM/GCM and SHA-512 plus HMAC-SHA256 counter-mode derivation; do not implement cipher primitives locally. The unchanged NTLMv2 exchange supplies the exported session key. Separate directional keys and exact transcript binding prevent cross-direction use and altered 3.1.1 negotiation. 3.0/3.0.2 retain signed negotiate validation.

Highest-common 3.1.1 is the modern default. Signed 2.1 compatibility remains available. Encryption is client-selected, so clients that require confidentiality must explicitly require it and constrain their minimum dialect. The service advertises only the algorithm/capability subset implemented and tested. GMAC, AES-256, compression and additional transports are deferred.

Validate the whole transform and all compound headers/signatures before file operations. Use the credit MessageId window for replay rejection, a bounded nonce set for received nonce reuse, and random-prefix/counter outbound nonces. Close after 65,536 encrypted frames per direction to bound memory; automatic rekey is deferred. Connections cannot bind additional sessions/channels. Errors in authentication/secure negotiation close the connection and stop later compound commands.

Caching, notification, durable/persistent handles and multichannel are independent features. Grant none; explicitly reject durable reconnect, notification and binding. This preserves immediate shared-authority consistency and honest restart semantics: authenticate again and reopen, with committed delete intents recovered by the file authority. The [M6 guide](../m6.md) and [evidence](../evidence/m6/README.md) define the selected profile; the broader native-client/Samba release gate remains open.
