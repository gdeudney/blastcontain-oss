"""Private local run files and process leases; never signal a PID from disk."""

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import uuid

from ..contracts import ContractError
from ..plugins.catalog import parse_json
from .artifacts import canonical, safe_path

MAX_FILE = 16 * 1024 * 1024


def _windows_acl(path, *, restrict=False):
    # Native DACLs, not chmod's read-only flag. See the linked Microsoft API docs
    # in suite-runs.md. Each descriptor allows only the current process user.
    import ctypes as c
    from ctypes import wintypes as w

    adv = getattr(c, "WinDLL")("advapi32", use_last_error=True)
    kernel = getattr(c, "WinDLL")("kernel32", use_last_error=True)
    ptr = c.c_void_p

    def function(library, name, result, args):
        fn = getattr(library, name)
        fn.restype, fn.argtypes = result, args
        return fn

    local_free = function(kernel, "LocalFree", ptr, [ptr])
    get_process = function(kernel, "GetCurrentProcess", w.HANDLE, [])
    close = function(kernel, "CloseHandle", w.BOOL, [w.HANDLE])
    open_token = function(adv, "OpenProcessToken", w.BOOL, [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)])
    token_info = function(
        adv, "GetTokenInformation", w.BOOL, [w.HANDLE, c.c_int, ptr, w.DWORD, c.POINTER(w.DWORD)]
    )
    sid_text = function(adv, "ConvertSidToStringSidW", w.BOOL, [ptr, c.POINTER(ptr)])
    convert = function(
        adv,
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        w.BOOL,
        [w.LPCWSTR, w.DWORD, c.POINTER(ptr), ptr],
    )
    get_dacl = function(
        adv,
        "GetSecurityDescriptorDacl",
        w.BOOL,
        [ptr, c.POINTER(w.BOOL), c.POINTER(ptr), c.POINTER(w.BOOL)],
    )
    set_info = function(
        adv, "SetNamedSecurityInfoW", w.DWORD, [w.LPWSTR, c.c_int, w.DWORD, ptr, ptr, ptr, ptr]
    )
    get_info = function(
        adv,
        "GetNamedSecurityInfoW",
        w.DWORD,
        [w.LPCWSTR, c.c_int, w.DWORD, c.POINTER(ptr), ptr, c.POINTER(ptr), ptr, c.POINTER(ptr)],
    )
    equal = function(adv, "EqualSid", w.BOOL, [ptr, ptr])
    acl_info = function(adv, "GetAclInformation", w.BOOL, [ptr, ptr, w.DWORD, c.c_int])
    get_ace = function(adv, "GetAce", w.BOOL, [ptr, w.DWORD, c.POINTER(ptr)])
    token, size = w.HANDLE(), w.DWORD()
    allocations = []
    try:
        if not open_token(get_process(), 8, c.byref(token)):
            raise ContractError("Cannot establish private Windows storage")
        token_info(token, 1, None, 0, c.byref(size))
        buffer = c.create_string_buffer(size.value)
        if not token_info(token, 1, buffer, size, c.byref(size)):
            raise ContractError("Cannot read current Windows identity")
        sid = c.cast(buffer, c.POINTER(ptr))[0]
        if restrict:
            text, descriptor, dacl = ptr(), ptr(), ptr()
            if not sid_text(sid, c.byref(text)):
                raise ContractError("Cannot encode Windows identity")
            allocations.append(text)
            sddl = f"D:P(A;OICI;FA;;;{c.wstring_at(text)})"
            if not convert(sddl, 1, c.byref(descriptor), None):
                raise ContractError("Cannot construct private DACL")
            allocations.append(descriptor)
            present, defaulted = w.BOOL(), w.BOOL()
            if (
                not get_dacl(descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted))
                or not present
            ):
                raise ContractError("Cannot construct private DACL")
            if set_info(str(path), 1, 1 | 4 | 0x80000000, sid, None, dacl, None):
                raise ContractError("Cannot protect Windows run directory")
        owner, dacl, descriptor = ptr(), ptr(), ptr()
        if get_info(
            str(path), 1, 1 | 4, c.byref(owner), None, c.byref(dacl), None, c.byref(descriptor)
        ):
            raise ContractError("Cannot inspect Windows run permissions")
        allocations.append(descriptor)
        counts = (w.DWORD * 3)()
        if (
            not dacl
            or not equal(owner, sid)
            or not acl_info(dacl, counts, c.sizeof(counts), 2)
            or counts[0] != 1
        ):
            raise ContractError("Run storage must belong exclusively to the current user")
        ace = ptr()
        if not get_ace(dacl, 0, c.byref(ace)) or ace.value is None:
            raise ContractError("Cannot inspect Windows run permissions")
        header = (c.c_ubyte * 4).from_address(ace.value)
        mask = w.DWORD.from_address(ace.value + 4).value
        if (
            header[0] != 0
            or header[1] & 8
            or mask & 0x1F01FF != 0x1F01FF
            or not equal(ace.value + 8, sid)
        ):
            raise ContractError("Run storage must allow only its owner")
    finally:
        for allocation in allocations:
            local_free(allocation)
        if token:
            close(token)


def private(path: Path, *, directory=False):
    safe_path(path)
    if os.name == "nt" and any(
        getattr(parent.lstat(), "st_file_attributes", 0) & 0x400 for parent in (path, *path.parents)
    ):
        raise ContractError("Run storage cannot traverse Windows reparse points")
    info = path.lstat()
    if getattr(info, "st_file_attributes", 0) & 0x400:
        raise ContractError("Run storage cannot use Windows reparse points")
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ContractError("Expected an unlinked private run file or directory")
    if os.name == "nt":
        _windows_acl(path)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ContractError("Run storage must be owner-only")
    return info


def mkdir_private(path: Path):
    safe_path(path)
    path.mkdir(
        mode=0o700
    )  # Caller must supply an existing parent; never chmod arbitrary ancestors.
    if os.name == "nt":
        _windows_acl(path, restrict=True)
    private(path, directory=True)


def read_private(path: Path, maximum=MAX_FILE):
    private(path.parent, directory=True)
    before = private(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (info.st_ino, info.st_dev) != (before.st_ino, before.st_dev) or info.st_size > maximum:
            raise ContractError("Run file changed or exceeds its size limit")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ContractError("Run file exceeds its size limit")
    return data


def read_json(path, maximum=MAX_FILE):
    return parse_json(read_private(path, maximum))


def write_private(path: Path, data: bytes, *, replace=False):
    private(path.parent, directory=True)
    if len(data) > MAX_FILE:
        raise ContractError("Run file exceeds its size limit")
    if path.exists() or path.is_symlink():
        private(path)
        if not replace:
            raise FileExistsError("Run file already exists")
    temporary = path.with_name(".write-" + uuid.uuid4().hex)
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            _windows_acl(temporary, restrict=True)
        private(temporary)
        if replace:
            os.replace(temporary, path)
        else:
            # Atomic no-replace publication, including concurrent lease creators.
            os.link(temporary, path)
            temporary.unlink()
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, data, *, replace=False):
    write_private(path, canonical(data) + b"\n", replace=replace)


@contextmanager
def lease(path: Path):
    """Nonblocking OS lock, released by process death. No stored PID is consulted."""
    if not path.exists():
        try:
            write_private(path, b"0")
        except FileExistsError:
            pass
    private(path)
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    locked = False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                getattr(msvcrt, "locking")(fd, getattr(msvcrt, "LK_NBLCK"), 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            pass
        yield locked
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                getattr(msvcrt, "locking")(fd, getattr(msvcrt, "LK_UNLCK"), 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
