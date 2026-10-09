"""
Load generator for the stress tests.

Sends bursts of concurrent requests, waits for every request in the
burst to complete, pauses, and repeats until the duration is up. The
pause matters: a process configured with a maximum number of requests
only restarts once no request is in flight, so continuous load would
keep it alive and the restart path would never be exercised.

Requests are spread across the paths given in turn. A summary is
printed per path and then one TOTAL line which the stress runner reads.

Usage:
    burst.py --port PORT --duration SECONDS --concurrency N
             --pause SECONDS PATH [PATH ...]
"""

import argparse
import http.client
import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--duration', type=float, required=True)
    parser.add_argument('--concurrency', type=int, required=True)
    parser.add_argument('--pause', type=float, required=True)
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()

    counter = itertools.count()
    lock = threading.Lock()
    results = {}

    def one(_):
        path = args.paths[next(counter) % len(args.paths)]

        try:
            connection = http.client.HTTPConnection(args.host, args.port,
                                                    timeout=60)
            connection.request('GET', path)
            status = str(connection.getresponse().status)
            connection.close()
        except Exception as exc:
            status = type(exc).__name__

        with lock:
            results[(path, status)] = results.get((path, status), 0) + 1

    deadline = time.monotonic() + args.duration
    bursts = 0

    with ThreadPoolExecutor(args.concurrency) as executor:
        while time.monotonic() < deadline:
            list(executor.map(one, range(args.concurrency)))
            bursts += 1
            time.sleep(args.pause)

    total = 0
    ok = 0

    for path in args.paths:
        for (result_path, status), count in sorted(results.items()):
            if result_path != path:
                continue
            print('%-40s %-24s %d' % (path, status, count))
            total += count
            if status == '200':
                ok += count

    print('TOTAL bursts=%d requests=%d ok=%d errors=%d' % (
        bursts, total, ok, total - ok))


if __name__ == '__main__':
    main()
