# SMB asynchronous compound transport

At `0bf303f`, native Linux CIFS/Kerberos completed write, read, rename and
truncate, then failed directory enumeration with EAGAIN and `RFC 1002 unknown
response type 0xfe`. The macOS native client failed during rename with
`RPC struct is bad`; its preceding directory query received a synchronous
CREATE result and pending QUERY_DIRECTORY/CLOSE results in one compound frame.
The macOS NFSv3 roundtrip passed in that same run.

Linux's receive loop returns to reading a transport header after a pending
response, without consuming the remaining compound segments. Apple's receive
path handles standalone interim notifications separately from final compound
results. These paths explain why the independent Python client could accept
the previous response layout while native clients failed.

The dispatcher now sends every response in a batch separately if any operation
in that batch is pending. Each frame has zero NextCommand and no RELATED flag;
signatures cover the final header and padding, and each encrypted frame uses a
fresh nonce. Completed prefixes cannot imply that pending suffixes are final.
Entirely synchronous compounds retain their existing layout. Request execution,
inherited FileIds, distinct AsyncIds, one-time credit grants, cancellation and
dependent failure propagation retain their existing behavior. Per-response
signing keys survive session retirement within the batch and are cleared when
the bounded response collection leaves scope.

This follows the permitted separate-response behavior in
[MS-SMB2 3.3.4.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dde8b59f-52ca-4cf8-8253-211bc43639cf)
and the interim-response format in
[MS-SMB2 3.3.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c1692ece-7c6d-45c8-a0e3-6b53c0483030).
Client implementation references are
[Linux CIFS connect.c](https://github.com/torvalds/linux/blob/v6.19/fs/smb/client/connect.c)
(`cifs_handle_standard` and `cifs_demultiplex_thread`) and
[Apple SMBClient smb_iod.c](https://github.com/apple-oss-distributions/SMBClient/blob/main/kernel/netsmb/smb_iod.c)
(interim processing and `SMBV_NON_COMPOUND_REPLIES`).

Independent tests inspect actual signed/decrypted receive boundaries across
SMB 2.1, 3.0, 3.0.2 and 3.1.1. They cover both all-pending chains and mixed
synchronous prefixes, delayed locks, resumed waits, dependent CREATE, cancel,
teardown and the bounded pending queue. Native acceptance now retains all
compound headers in its metadata relay, including the Linux Kerberos mount.
The relay forwards bytes unchanged and never records authentication tokens,
session keys or file contents.

[Local evidence](evidence/pre-m8/smb-compound-framing-local.json) retains the
pre-fix reproduction, final component results and remaining unmodified Samba
failures. The complete Full SMB/NFS gate and fixed-source native reacceptance
remain open. `related3` now passes locally with the separately implemented
[persistent object-ID IOCTL](smb-object-identifiers.md). `interim2` expects Windows' special rejection of
an indefinite non-final CHANGE_NOTIFY, and `write_write`/`read_read` expect
asynchronous scheduling for otherwise immediately completed I/O. The separate
`compound-padding` case stops at its unsupported named-stream prerequisite;
it does not yet reach its padding assertions. Original `interim1`,
`compound-break`, `create-write-close`, `flush_close` and `flush_flush` pass.

## Directory initialization after cache recall

Fixed-source Linux CIFS acceptance at `ed77b4d` gets past the earlier transport
framing error but receives premature NO_MORE_FILES during its first directory
query. A related CREATE/QUERY_DIRECTORY compound triggers a child-file cache
recall; QUERY_DIRECTORY saved its search pattern before the file-domain list
completed. Retrying the operation then treated the unfinished first query as
a continuation of an empty enumeration.

The search pattern, entries and initial cursor are now published together only
after list, self metadata and parent metadata operations succeed. A cache break
leaves the original initialization state intact. The independent signed/encrypted
client regression reproduces NO_MORE_FILES on the old binary, then passes across
SMB 2.1, 3.0, 3.0.2 and 3.1.1 with the fix. It requires an actual pending request
and unsolicited cache recall, keeps ECHO responsive, flushes/acknowledges the
holder, checks all entries and then checks normal end-of-enumeration. Existing
asynchronous compound tests also pass. See
[before/after evidence](evidence/pre-m8/smb-directory-retry-local.json).

A dedicated Linux Actions job now runs real Kerberos CIFS mounts directly after
build, in addition to the full metadata matrix. Native reacceptance on this
change is pending. macOS SMB still fails at `ed77b4d`; its NFSv3 client passes.
No full native-client compatibility is claimed from the independent-client tests.

The retained [macOS result](evidence/pre-m8/macos-ed77-native-failure.json) fails
during the first payload write with EBADF/STATUS_FILE_CLOSED, rather than the
previous rename framing error. Its metadata artifact was byte-truncated into
invalid JSON and mixed different connections' message IDs. The harness now
retains the complete 512-frame-bounded metadata document and labels connection
numbers and opaque CREATE/CLOSE/IO FileIds. It still omits authentication blobs,
keys and file data. This improves diagnosis; the macOS defect is not yet fixed.
