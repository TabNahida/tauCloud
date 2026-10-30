# NFSv4.1 operation coverage

This is an implementation and test map for the regular-file/directory AUTH_SYS profile. It is not a declaration of complete RFC 8881 conformance. The [RFC operation table](https://www.rfc-editor.org/rfc/rfc8881.html#section-17) is the source of the required/optional distinction. RPCSEC_GSS and SSV authentication remain the explicitly deferred authenticated profile; no backchannel, delegation or pNFS layout is granted.

| Required operations | Implementation | Executable evidence |
| --- | --- | --- |
| EXCHANGE_ID, CREATE_SESSION, DESTROY_SESSION, DESTROY_CLIENTID | `src/nfs_v4.inc`, bounded clients/sessions and identity ownership | Upstream `exchange_id`, `create_session`, `destroy_session`, `destroy_clientid` cases in `pynfs-control.json`; `tests/m7_integration.py` |
| SEQUENCE | Per-slot sequence/replay, bounded responses, principal-bound request identity and renewed authorization | Upstream `sequence`; `tests/nfs_namespace_integration.py`, `tests/nfs_state_integration.py` |
| BIND_CONN_TO_SESSION | Fore-channel connection binding, SP4_NONE implicit binding | `tests/nfs_state_integration.py` binds a fresh TCP connection and uses the existing session |
| BACKCHANNEL_CTL, SET_SSV | Bounded callback security configuration; unknown GSS handles return NOENT; SSV is INVAL for negotiated SP4_NONE | `tests/nfs_discovery_integration.py` |
| PUTFH, PUTROOTFH, PUTPUBFH, GETFH, SAVEFH, RESTOREFH | Validated opaque handles and saved/current filehandle/stateid | `tests/m7_integration.py`, `tests/nfs_state_integration.py`; upstream PUTFH and current-stateid cases |
| LOOKUP, LOOKUPP, ACCESS, GETATTR | Authorized pseudo-root, exports, parents, attributes and policy access projection | `tests/nfs_namespace_integration.py`, `tests/nfs_attributes_integration.py`; upstream namespace profile |
| VERIFY, NVERIFY | Attribute comparison with explicit unsupported/write-only attribute errors | Upstream regular-file/directory profile and VF1r |
| OPEN, OPEN_DOWNGRADE, CLOSE | Principal-owned state, share-deny, creation, upgrade/downgrade, retained unlinked objects | `tests/nfs_create_integration.py`, `tests/nfs_state_integration.py`, `tests/nfs_unlink_integration.py`; upstream OPEN/current-stateid cases |
| LOCK, LOCKT, LOCKU, FREE_STATEID, TEST_STATEID | Owned shared/exclusive ranges, partial unlock, old/current state validation and explicit state release | `tests/nfs_state_integration.py`, `tests/nlm_integration.py`; core state tests |
| RECLAIM_COMPLETE | Global/per-filesystem recovery completion and persisted OPEN/lock reclaim | `tests/m7_integration.py`, `tests/nfs_state_integration.py`, `tests/nfs_unlink_integration.py`; upstream reclaim cases |
| READ, WRITE, COMMIT, SETATTR | 64 KiB I/O, FILE_SYNC, quota, timestamps and durable change counters | `tests/m7_integration.py`, `tests/nfs_attributes_integration.py`, `tests/nfs_create_integration.py` |
| CREATE, REMOVE, RENAME, READDIR | Regular-file/directory namespace, replacement, retained opens, page cookies/change_info | `tests/nfs_namespace_integration.py`, `tests/nfs_unlink_integration.py`, `tests/nfs_pin_recovery_integration.py`; upstream regular-file/directory profile |
| SECINFO | Authorized AUTH_SYS security discovery | `tests/nfs_namespace_integration.py`; upstream SEC cases |

Recommended SECINFO_NO_NAME is implemented and covered by SECNN cases. Optional GET_DIR_DELEGATION returns GDD4_UNAVAIL without promising a callback. LINK, READLINK, OPENATTR, DELEGPURGE, DELEGRETURN, GETDEVICEINFO, GETDEVICELIST, LAYOUTCOMMIT, LAYOUTGET, LAYOUTRETURN and WANT_DELEGATION are recognized and return NOTSUPP under this profile. `tests/nfs_discovery_integration.py` verifies their operation numbers and stops the compound at the unsupported operation. Optional special-file creation returns BADTYPE.

The obsolete v4.0 operations OPEN_CONFIRM, RENEW, SETCLIENTID, SETCLIENTID_CONFIRM and RELEASE_LOCKOWNER are decoded and return NOTSUPP. Unknown operation numbers return OP_ILLEGAL. No unsupported operation is reported as a successful implementation.

The upstream regular-file/directory invocation is `all nodeleg noblock nochar nofifo nosocket nosymlink noRNM20`: the recorded result is 145 passed, 121 not selected, zero failed. The omitted cases remain visible in the report. RNM20 requires hardlinks; RNM21 replacement and trunking cases are included. Native kernel close-to-open cache revalidation, native NLM reboot recovery and Windows Client for NFS results are separately required; operation coverage alone cannot establish those results.
