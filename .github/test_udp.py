import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from socket import AF_INET, SOCK_DGRAM, gethostbyname, socket
from time import perf_counter

import pandas as pd
import plotext as plt

# Configuration options
PACKETS_TO_SEND = 1000
WORKERS = 16
FAILURE_THRESHOLD = 0.02
SOCKET_TIMEOUT = 1


def sendPacket(host):
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    start_time = perf_counter()
    sock.sendto(b"ping", (host, random.randrange(1, 65535)))
    try:
        data, _ = sock.recvfrom(1024)
        end_time = perf_counter()
        assert data == b"ping"
    except:
        return -1

    return (end_time - start_time) * 1000


def main():
    if len(sys.argv) != 2:
        print("Usage: python test_udp.py SERVER")
        sys.exit(1)

    host = gethostbyname(sys.argv[1])

    rtt = []
    failures = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        print(f"Sending {PACKETS_TO_SEND} packets to {host}")
        futures = [executor.submit(sendPacket, host) for _ in range(PACKETS_TO_SEND)]

        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result == -1:
                failures += 1
            else:
                rtt.append(result)
            print(
                f"\r{i}/{PACKETS_TO_SEND} packets sent (failures: {failures})", flush=True, end=""
            )

    print()

    plt.hist(rtt, bins=10)
    plt.show()

    print(f"{failures} failures")
    print(pd.Series(rtt).describe())

    # Return non-zero exit code if failure% > FAILURE_THRESHOLD
    if failures > PACKETS_TO_SEND * FAILURE_THRESHOLD:
        sys.exit(1)


if __name__ == "__main__":
    main()
