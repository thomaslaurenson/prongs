import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue

import paramiko

from .. import config

# Suppress paramiko's internal transport error logging - these are handled exceptions
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

PROGRESS_COUNTER = 0


def check_ssh_password_auth(ip: str, port: int, result_queue: Queue) -> bool:
    global PROGRESS_COUNTER

    # First check port is open using socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
    except socket.error:
        result_queue.put((ip, port, False))
        PROGRESS_COUNTER += 1
        return

    # Reuse the existing socket - avoids a second connection and ensures it gets closed
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=2)

        # Try to authenticate with no authentication at all and a "random" username
        # We do this to get a list of available authentication methods
        # Check the available authentication methods for "password"
        try:
            transport.auth_none("cats_are_mythical")
        except paramiko.BadAuthenticationType as e:
            if "password" in e.allowed_types:
                result_queue.put((ip, port, True))
                PROGRESS_COUNTER += 1
                return
        except paramiko.SSHException:
            pass
    except (paramiko.SSHException, socket.error):
        pass
    finally:
        if transport:
            transport.close()
        else:
            sock.close()

    PROGRESS_COUNTER += 1
    result_queue.put((ip, port, False))


def run(hosts: list[ipaddress.IPv4Network]) -> None:
    result_queue = Queue()

    total_hosts = len(hosts)
    max_workers = 100
    progress_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_ssh_password_auth, str(ip), 22, result_queue) for ip in hosts]

        while any(future.running() for future in futures):
            with progress_lock:
                if config.pretty_print:
                    print(f"\rProgress: {PROGRESS_COUNTER}/{total_hosts}", end="")
            time.sleep(1)

    for future in futures:
        future.result()

    if config.pretty_print:
        print(f"\rProgress: {PROGRESS_COUNTER}/{total_hosts}")

    while not result_queue.empty():
        ip, port, status = result_queue.get()
        if status:
            if config.pretty_print:
                print(f"🚨 {ip}:{port} allows password authentication")
            else:
                print(f"{datetime.now(timezone.utc).isoformat()}\t{ip}\tpassword-ssh\t22")

    if config.pretty_print:
        print(f"Total hosts/checks: {total_hosts}/{PROGRESS_COUNTER}")


def main():
    config.pretty_print = True
    run(config.test_host)


if __name__ == "__main__":
    main()
