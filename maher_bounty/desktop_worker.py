"""CLI subprocess wrapper with cooperative desktop cancellation on POSIX."""
import os
import signal
import sys


def main():
    if os.name == "posix":
        def stop(signum, frame):
            # Let active adapters' finally/exception paths clean their own
            # private process sessions before the desktop's forced fallback.
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
    from .cli import main as cli_main
    try:
        return cli_main()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
