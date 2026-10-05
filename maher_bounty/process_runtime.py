"""Subprocess execution with bounded cleanup of the complete tool process tree."""
import os
import signal
import subprocess


class _WindowsJob:
    def __init__(self, process):
        import ctypes
        from ctypes import wintypes
        class Limits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
                        ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("limits", Limits), ("io", Counters), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        limits = Extended()
        limits.limits.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.handle or not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise OSError("could not create process-tree job")
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close()
            raise OSError("could not assign tool to process-tree job")

    def terminate(self):
        self.api.TerminateJobObject(self.handle, 1)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def _kill_tree(process, job=None):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif job:
        job.terminate()
    else:
        # taskkill uses PID arguments, never a shell-built command.
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if process.poll() is None:
        process.kill()


def run(cmd, *, input=None, capture_output=False, stdout=None, stderr=None,
        text=False, timeout=None, check=False):
    if capture_output:
        if stdout is not None or stderr is not None:
            raise ValueError("capture_output conflicts with stdout/stderr")
        stdout = stderr = subprocess.PIPE
    options = {"start_new_session": True} if os.name == "posix" else {
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
    }
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE if input is not None else None,
                               stdout=stdout, stderr=stderr, text=text, **options)
    job = None
    try:
        if os.name == "nt":
            job = _WindowsJob(process)
        output, errors = process.communicate(input=input, timeout=timeout)
        result = subprocess.CompletedProcess(cmd, process.returncode, output, errors)
        if check:
            result.check_returncode()
        return result
    except subprocess.TimeoutExpired as exc:
        _kill_tree(process, job)
        try:
            output, errors = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # A descendant outside the group may retain pipe handles. Never
            # wait indefinitely in the cleanup path.
            output, errors = exc.output, exc.stderr
            # On Windows a reader thread can hold the stream lock. Closing
            # that stream here would itself wait for an escaped descendant.
        raise subprocess.TimeoutExpired(cmd, timeout, output=output, stderr=errors) from None
    except BaseException:
        _kill_tree(process, job)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        if job:
            job.close()
