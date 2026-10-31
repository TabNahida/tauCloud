"""Independent host-filesystem allocation oracle for protocol integration tests."""
import os


def native_allocation(path):
    if os.name != 'nt':
        return path.stat().st_blocks * 512
    import ctypes
    import struct
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   wintypes.LPVOID, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0, None)
    assert handle != ctypes.c_void_p(-1).value, ctypes.get_last_error()
    try:
        info = ctypes.create_string_buffer(24)
        assert kernel.GetFileInformationByHandleEx(handle, 1, info, len(info)), ctypes.get_last_error()
        return struct.unpack_from('<Q', info.raw)[0]
    finally:
        kernel.CloseHandle(handle)
