"""Subprocess execution with bounded cleanup of the complete tool process tree."""
import os
import signal
import subprocess
import threading
import time


class OutputLimitExceeded(subprocess.TimeoutExpired):
    """Captured output exceeded its budget; partial output is bounded."""
    def __init__(self, cmd, timeout, limit, output=None, stderr=None):
        super().__init__(cmd, timeout, output=output, stderr=stderr)
        self.limit = limit


def _bounded_communicate(process, cmd, input, timeout, limit, text, job):
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = threading.Event()
    lock = threading.Lock()
    threads = []
    io_errors = []
    def reader(stream, key):
        try:
            while True:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                with lock:
                    remaining = limit - sum(len(b) for b in buffers.values())
                    buffers[key].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        exceeded.set()
        except OSError as exc:
            with lock:
                io_errors.append(exc)
            exceeded.set()
        finally:
            stream.close()
    for key in buffers:
        stream = getattr(process, key)
        if stream:
            thread = threading.Thread(target=reader, args=(stream, key), daemon=True)
            thread.start()
            threads.append(thread)
    def writer():
        try:
            process.stdin.write(input.encode("utf-8") if isinstance(input, str) else input)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        except OSError as exc:
            with lock:
                io_errors.append(exc)
            exceeded.set()
        finally:
            process.stdin.close()
    if input is not None:
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        threads.append(thread)
    deadline = time.monotonic() + timeout if timeout is not None else None
    failure = None
    try:
        while True:
            if exceeded.is_set():
                failure = "output"
                break
            if process.poll() is not None and not any(t.is_alive() for t in threads):
                break
            if deadline is not None and time.monotonic() >= deadline:
                failure = "timeout"
                break
            exceeded.wait(0.01)
    finally:
        if exceeded.is_set() and failure is None:
            failure = "output"
        if failure or process.poll() is None or any(t.is_alive() for t in threads):
            _kill_tree(process, job)
        cleanup_deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(max(0, cleanup_deadline - time.monotonic()))
        try:
            process.wait(timeout=max(0.01, cleanup_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    with lock:
        def captured(key):
            if getattr(process, key) is None:
                return None
            data = bytes(buffers[key])
            return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n") if text else data
        output, errors = captured("stdout"), captured("stderr")
        io_error = io_errors[0] if io_errors else None
    if io_error:
        raise io_error
    if failure == "output":
        raise OutputLimitExceeded(cmd, timeout, limit, output, errors)
    if failure:
        raise subprocess.TimeoutExpired(cmd, timeout, output=output, stderr=errors)
    return output, errors


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
        text=False, timeout=None, check=False, max_output_bytes=8 * 1024 * 1024):
    if type(max_output_bytes) is not int or max_output_bytes < 1:
        raise ValueError("max_output_bytes must be a positive integer")
    if capture_output:
        if stdout is not None or stderr is not None:
            raise ValueError("capture_output conflicts with stdout/stderr")
        stdout = stderr = subprocess.PIPE
    options = {"start_new_session": True} if os.name == "posix" else {
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
    }
    bounded = stdout == subprocess.PIPE or stderr == subprocess.PIPE
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE if input is not None else None,
                               stdout=stdout, stderr=stderr, text=text and not bounded, **options)
    job = None
    try:
        if os.name == "nt":
            job = _WindowsJob(process)
        if bounded:
            output, errors = _bounded_communicate(process, cmd, input, timeout, max_output_bytes, text, job)
        else:
            output, errors = process.communicate(input=input, timeout=timeout)
        result = subprocess.CompletedProcess(cmd, process.returncode, output, errors)
        if check:
            result.check_returncode()
        return result
    except subprocess.TimeoutExpired as exc:
        if bounded:
            raise
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
