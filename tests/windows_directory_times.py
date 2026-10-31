#!/usr/bin/env python3
"""Isolated Win32 directory-handle diagnostic; no server or account changes."""
import ctypes,json,os,tempfile
from ctypes import wintypes as w
from pathlib import Path
assert os.name=='nt'
k=ctypes.WinDLL('kernel32',use_last_error=True);nt=ctypes.WinDLL('ntdll')
k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
k.ReOpenFile.argtypes=[w.HANDLE,w.DWORD,w.DWORD,w.DWORD];k.ReOpenFile.restype=w.HANDLE
k.FlushFileBuffers.argtypes=[w.HANDLE];k.FlushFileBuffers.restype=w.BOOL
k.CloseHandle.argtypes=[w.HANDLE]
k.SetFileTime.argtypes=[w.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(w.FILETIME)];k.SetFileTime.restype=w.BOOL
class Unicode(ctypes.Structure):_fields_=[('Length',w.USHORT),('MaximumLength',w.USHORT),('Buffer',w.LPWSTR)]
class Attributes(ctypes.Structure):_fields_=[('Length',w.ULONG),('RootDirectory',w.HANDLE),('ObjectName',ctypes.POINTER(Unicode)),('Attributes',w.ULONG),('SecurityDescriptor',ctypes.c_void_p),('SecurityQualityOfService',ctypes.c_void_p)]
class Io(ctypes.Structure):_fields_=[('Status',ctypes.c_void_p),('Information',ctypes.c_size_t)]
nt.NtCreateFile.argtypes=[ctypes.POINTER(w.HANDLE),w.DWORD,ctypes.POINTER(Attributes),ctypes.POINTER(Io),ctypes.c_void_p,w.ULONG,w.ULONG,w.ULONG,w.ULONG,ctypes.c_void_p,w.ULONG];nt.NtCreateFile.restype=ctypes.c_long
invalid=ctypes.c_void_p(-1).value
results=[]
with tempfile.TemporaryDirectory(prefix='tc-time-') as temp:
    parent=k.CreateFileW(temp,0x80000000|0x100000,3,None,3,0x02000000|0x00200000,None)
    assert parent!=invalid
    try:
        name=ctypes.create_unicode_buffer('child');u=Unicode(10,10,ctypes.cast(name,w.LPWSTR));attr=Attributes(ctypes.sizeof(Attributes),parent,ctypes.pointer(u),0x40,None,None);io=Io();handle=w.HANDLE()
        status=nt.NtCreateFile(ctypes.byref(handle),0x80000000|0x100000,ctypes.byref(attr),ctypes.byref(io),None,0x80,3,2,0x00200000|0x20|1,None,0)
        results.append(dict(operation='NtCreateFile directory',status=hex(status&0xffffffff)))
        if status>=0:
            try:
                ok=k.FlushFileBuffers(handle);results.append(dict(operation='FlushFileBuffers directory',ok=bool(ok),error=ctypes.get_last_error()))
                again=k.ReOpenFile(handle,0x100,7,0x02000000)
                results.append(dict(operation='ReOpenFile WRITE_ATTRIBUTES',ok=again!=invalid,error=ctypes.get_last_error()))
                if again!=invalid:
                    ticks=116444736000000000+17000000007654321;t=w.FILETIME(ticks&0xffffffff,ticks>>32)
                    ok=k.SetFileTime(again,None,None,ctypes.byref(t));results.append(dict(operation='SetFileTime',ok=bool(ok),error=ctypes.get_last_error()));k.CloseHandle(again)
                metadata=w.HANDLE();io=Io()
                code=nt.NtCreateFile(ctypes.byref(metadata),0x80|0x100|0x100000,ctypes.byref(attr),ctypes.byref(io),None,0,3,1,0x00200000|0x20|1,None,0)
                results.append(dict(operation='relative pinned-parent metadata open',status=hex(code&0xffffffff)))
                if code>=0:
                    ticks=116444736000000000+17000000007654321;t=w.FILETIME(ticks&0xffffffff,ticks>>32)
                    ok=k.SetFileTime(metadata,None,None,ctypes.byref(t));results.append(dict(operation='relative directory SetFileTime',ok=bool(ok),error=ctypes.get_last_error()));k.CloseHandle(metadata)
            finally:k.CloseHandle(handle)
    finally:k.CloseHandle(parent)
print(json.dumps(results,indent=2))
