# Persistent SMB object identifiers

The server implements FSCTL_CREATE_OR_GET_OBJECT_ID (0x900c0) and
FSCTL_GET_OBJECT_ID (0x9009c) on regular-file and directory opens. Replies
contain the 64-byte FILE_OBJECTID_BUFFER and the actual open's SMB FileId.
The object identifier is separate from the volatile SMB handle and QFid's
native file number. The original Samba `smb2.compound.related3` now passes
locally, including CREATE, related object-ID IOCTL and CLOSE in one compound.

The wire contract follows [MS-FSCC CREATE_OR_GET](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a56345dc-13ed-4fee-aed1-f12afcb71be8),
[FILE_OBJECTID_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/34a727a2-960a-4825-9cd2-6100c84e3a81)
and [GET errors](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/09a79cae-b2d4-4e95-8bf7-c6526a88078f).
GET on an unassigned object returns STATUS_OBJECTID_NOT_FOUND. Short output
buffers, unexpected input, pipe handles and invalid handles are rejected
before creating metadata. The IS_FSCTL flag is required.

Windows delegates storage to NTFS's native DeviceIoControl operations, so
local applications observe the same identifier. Linux stores a private
`user.taucloud.object-id.v1` xattr through the confined descriptor and flushes
new records before reporting success. It contains a random UUID, zero birth
volume (Linux has no volume object ID here), matching birth object ID and zero
domain ID. The record includes the native incarnation used by the file core;
an xattr copied to another inode is not accepted as that inode's identifier.
Creation is serialized by the file authority, and XATTR_CREATE handles a
concurrent first assignment. Unsupported native filesystems return an error.

Every request refreshes its share/path authorization and checks the handle's
actor, storage domain and native incarnation. Existing IDs may be read through
a read-only share. Assigning a new ID requires a fresh write grant, even for
an open with only FILE_READ_ATTRIBUTES; the capability boundary remains in
the file worker. A native NFS delegation conflict is recalled before metadata
creation. No data handle is reopened for a regular-file IOCTL.

The independent test covers signed SMB 2.1 and encrypted 3.0, 3.0.2 and 3.1.1,
repeated queries, metadata-only opens, directories, SMB/native rename,
all-service restart, delete/recreate, copied xattrs and read-only authority.
The [local evidence](evidence/pre-m8/smb-object-id-local.json) also includes the
original Samba compound and DOS/EA regression. Actions runs the same tests
with GCC, Clang/sanitizers and Windows/MSVC; pending remote results are not
counted as passes.

Full object-ID compatibility remains open: SET/DELETE/EXTENDED operations,
volume object-ID assignment, link-tracking services and USN journal semantics
are not implemented. A Linux remount/device identity change has the same
identity limitations as the native file core and is not covered by process
restart acceptance. This work does not claim full SMB or NFS compatibility.
The copy test first creates its destination through SMB; an initial attempt
with an online, host-created destination exposed the separate missing
incremental namespace-index reconciliation. Native rename is tested while
services are stopped, followed by the existing startup reconciliation.

Windows acceptance at `b651aa1` passes all four dialects, metadata-only opens,
directories, restart and native rename, but its original same-name recreation
assertion fails because GET returns an identifier. The strengthened test now
requires completed native deletion and FILE_CREATE (not OPEN_IF), verifies a
new NTFS file incarnation, and compares SMB's identifier with direct local
DeviceIoControl. An independent delete/recreate on the same filesystem measures
whether native NTFS itself assigns an identifier during recreation. Linux's
no-inherited-xattr check remains strict. The Windows native-oracle result is
pending; the earlier failure is not counted as a pass.
