import mod_wsgi

from io import StringIO

# mod_wsgi.request_metrics() and mod_wsgi.process_metrics() return
# None until per-request and per-process recording is opted into at
# module import time via mod_wsgi.start_recording_metrics().
# mod_wsgi.server_metrics() does not depend on this call; its data
# comes from the Apache scoreboard and only requires
# WSGIServerMetrics On in the Apache config (and that mod_status is
# loaded so the scoreboard is populated).

mod_wsgi.start_recording_metrics()


def application(environ, start_response):
    headers = [('Content-Type', 'text/plain; charset="UTF-8"')]
    start_response('200 OK', headers)

    output = StringIO()

    print(f'mod_wsgi.process_group: {mod_wsgi.process_group}', file=output)
    print(f'mod_wsgi.application_group: {mod_wsgi.application_group}', file=output)
    print(f'mod_wsgi.maximum_processes: {mod_wsgi.maximum_processes}', file=output)
    print(f'mod_wsgi.threads_per_process: {mod_wsgi.threads_per_process}', file=output)
    print(file=output)

    print(f'mod_wsgi.request_metrics: {mod_wsgi.request_metrics()}', file=output)
    print(file=output)

    print(f'mod_wsgi.process_metrics: {mod_wsgi.process_metrics()}', file=output)
    print(file=output)

    print(f'mod_wsgi.server_metrics: {mod_wsgi.server_metrics()}', file=output)
    print(file=output)

    metrics = mod_wsgi.server_metrics()

    if metrics:
        # Per-worker scoreboard status flag string, joined across all
        # processes. Same flags as mod_status (W=writing reply,
        # K=keepalive, G=gracefully finishing, .=open slot,
        # _=waiting, etc.).

        for process in metrics['processes']:
            for worker in process['workers']:
                print(worker['status'], file=output, end='')
        print(file=output)
        print(file=output)

    return [output.getvalue().encode('UTF-8')]
