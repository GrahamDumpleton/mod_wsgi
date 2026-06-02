# Developer probe for mod_wsgi's event publication API. Hit this
# script under curl to fire the per-request events (request_started,
# response_started, request_finished, request_exception). Stop or
# restart Apache to fire process_stopping. In daemon mode, send
# SIGHUP or SIGUSR2 to the daemon PID (`kill -HUP <pid>` /
# `kill -USR2 <pid>`) to fire process_signal. Each handler prints
# its event name, payload, and a slice of related mod_wsgi runtime
# state to stderr so the publication order, payload shapes, and
# the active_requests / process_metrics() snapshots become
# observable in the Apache error log.

import mod_wsgi
import sys
import traceback
import time
import os
import threading
import atexit

# mod_wsgi.request_data() requires an active request bracket. The
# module-import-time call must therefore raise RuntimeError; the
# "mod_wsgi.request_data() at import time" line in the log
# confirms the contract holds at import time, as a counterpoint
# to the in-request reads done later.

try:
    mod_wsgi.request_data()
except RuntimeError:
    print('mod_wsgi.request_data() at import time:'
          ' RuntimeError raised as expected (no active request)')

# Trivial WSGI middleware. Installed at runtime by the
# request_started branch of event_handler below via the
# application_object replacement protocol. A "wrapper middleware
# invoked" line per request in the log demonstrates that the
# return-dict merge took effect and that subsequent dispatch
# resolved the wrapper rather than the original callable.

def wrapper(application):
    def _application(environ, start_response):
        print(f'wrapper middleware invoked, wrapping application={application!r}')
        return application(environ, start_response)
    return _application

# Catch-all subscriber. Always logs the firing (event name, full
# payload, pid, and application_group) so the per-request
# publication order is visible in the log. Per-event branches then
# exercise specific runtime API:
#
#   request_started   write thread name/id into the request_data
#                     scratchpad and return a dict containing
#                     application_object=wrapper(...) to install
#                     middleware via the event return-dict merge,
#                     plus custom_marker so the second subscriber
#                     can probe shallow-merge propagation of a
#                     non-application_object key.
#   response_started  dump active_requests mid-flight so the
#                     in-progress entry is visible.
#   request_finished  print the per-request scratchpad to confirm
#                     it carries both the request_started writes
#                     and the application-side mod_wsgi.request_data
#                     write across the request lifecycle, then dump
#                     process_metrics() so the per-interval
#                     accumulators can be inspected per request.
#   request_exception format the (type, value, tb) exception_info
#                     tuple from the payload.
#   process_stopping  dump active_requests at shutdown.
#   process_signal    log the canonical signame and the platform
#                     signum so a side-by-side comparison with
#                     signal_handler below shows both subscription
#                     paths firing for the same delivery.

def event_handler(name, **kwargs):
    print(f'event_handler fired: name={name!r}'
          f' pid={os.getpid()}'
          f' application_group={mod_wsgi.application_group!r}'
          f' kwargs={kwargs!r}')
    if name == 'request_started':
        thread = threading.current_thread()
        request_data = kwargs['request_data']
        request_data['thread_name'] = thread.name
        request_data['thread_id'] = thread.ident
        return dict(
            application_object=wrapper(kwargs['application_object']),
            custom_marker='set-by-event_handler',
        )
    elif name == 'response_started':
        print(f'active_requests at response_started: {mod_wsgi.active_requests!r}')
    elif name == 'request_finished':
        print(f'request_data scratchpad at request_finished: {kwargs["request_data"]!r}')
        print(f'process_metrics at request_finished: {mod_wsgi.process_metrics()!r}')
    elif name == 'request_exception':
        exception_info = kwargs['exception_info']
        print('request_exception traceback follows:')
        traceback.print_exception(*exception_info)
    elif name == 'process_stopping':
        print(f'active_requests at process_stopping: {mod_wsgi.active_requests!r}')
    elif name == 'process_signal':
        print(f'event_handler saw process_signal:'
              f' signame={kwargs.get("signame")!r}'
              f' signum={kwargs.get("signum")!r}')

# event_callbacks is the per-interpreter list mod_wsgi walks when
# publishing. The prints below show, in order: the empty list
# before any registration; then [event_handler, second_subscriber]
# after both event subscriptions land; then the same list again
# after subscribe_shutdown (which populates a separate
# shutdown_callbacks list, also printed for contrast).

print(f'event_callbacks before any subscribe: {mod_wsgi.event_callbacks!r}')

mod_wsgi.subscribe_events(event_handler)

# Second subscriber, registered via the decorator form. Subscribers
# run in registration order, so this one runs after event_handler
# on every firing. Two probes in one:
#  - subscribe_events returns the callback unchanged, so the
#    decorator-form binding works exactly like a free-standing
#    function: this only logs if the line below runs without
#    rebinding the name to something else.
#  - dict-merge propagation: event_handler returns
#    {'application_object': ..., 'custom_marker': ...} at
#    request_started; mod_wsgi shallow-merges that into the live
#    event dict before dispatching to the next subscriber, so
#    custom_marker should be present here at request_started and
#    absent everywhere else (event_handler returns None at the
#    other events, and each event publish starts from a fresh
#    dict).

@mod_wsgi.subscribe_events
def second_subscriber(name, **kwargs):
    print(f'second_subscriber fired: name={name!r}'
          f' custom_marker={kwargs.get("custom_marker")!r}')

# subscribe_shutdown is the narrow-form subscription that only
# fires for process_stopping. shutdown_handler runs in addition to
# the process_stopping branch of event_handler above, so the
# shutdown log shows both subscription paths firing for the same
# event. The shutdown_reason payload key is mapped to a short
# operator-facing tag so the firing surfaces *what* triggered the
# shutdown rather than just the raw reason string. The empty
# string maps to EMBEDDED, since embedded mode has no daemon-side
# lifecycle visibility (Apache controls the child directly).

SHUTDOWN_REASON_TAGS = {
    '': 'EMBEDDED',
    'shutdown_signal': 'SHUTDOWN',
    'graceful_signal': 'GRACEFUL',
    'eviction_signal': 'EVICTION',
    'maximum_requests': 'MAX-REQUESTS',
    'restart_interval': 'RESTART-INTERVAL',
    'inactivity_timeout': 'INACTIVITY',
    'request_timeout': 'REQUEST-TIMEOUT',
    'startup_timeout': 'STARTUP-TIMEOUT',
    'deadlock_timeout': 'DEADLOCK',
    'cpu_time_limit': 'CPU-LIMIT',
    'signal_pipe_error': 'SIGNAL-PIPE',
    'script_reload': 'SCRIPT-RELOAD',
}

def shutdown_handler(name, **kwargs):
    reason = kwargs.get('shutdown_reason', '')
    tag = SHUTDOWN_REASON_TAGS.get(reason, 'UNKNOWN')
    print(f'shutdown_handler fired: name={name!r}'
          f' shutdown_reason={reason!r} tag={tag}'
          f' kwargs={kwargs!r}')

print(f'event_callbacks after subscribe_events for both handlers:'
      f' {mod_wsgi.event_callbacks!r}')

mod_wsgi.subscribe_shutdown(shutdown_handler)

print(f'event_callbacks after subscribe_shutdown'
      f' (unchanged, shutdown is a separate list):'
      f' {mod_wsgi.event_callbacks!r}')
print(f'shutdown_callbacks after subscribe_shutdown:'
      f' {mod_wsgi.shutdown_callbacks!r}')

# subscribe_signals is the narrow-form subscription for the
# process_signal event mod_wsgi publishes when the daemon process
# receives SIGHUP or SIGUSR2. Like subscribe_shutdown, this
# populates a separate per-interpreter callback list
# (signal_callbacks) and runs in addition to the process_signal
# branch of event_handler above, so a single delivery produces
# entries from both the catch-all and the narrow subscriber for
# direct comparison in the log.
#
# In embedded mode the call is intentionally tolerated: it logs an
# APLOG_INFO warning plus a Python stack trace identifying this
# call site, discards the callback, and returns it unchanged so
# the decorator-form binding below is still callable. The
# signal_callbacks list also stays empty in embedded mode (the
# warning is the discovery channel, not a stub registration). In
# service-script daemons (threads=0) the call is accepted and the
# list is populated, but the dispatcher infrastructure is never
# started so the callback never fires.

@mod_wsgi.subscribe_signals
def signal_handler(name, **kwargs):
    print(f'signal_handler fired: name={name!r}'
          f' signame={kwargs.get("signame")!r}'
          f' signum={kwargs.get("signum")!r}'
          f' pid={os.getpid()}'
          f' application_group={mod_wsgi.application_group!r}')

print(f'event_callbacks after subscribe_signals'
      f' (unchanged, signal is a separate list):'
      f' {mod_wsgi.event_callbacks!r}')
print(f'signal_callbacks after subscribe_signals:'
      f' {mod_wsgi.signal_callbacks!r}')

# atexit fires during Python's interpreter finalisation, after the
# non-daemon-thread join, so it runs strictly after
# process_stopping. Registered here so the relative ordering of the
# two cleanup hooks is observable side-by-side in the log at
# shutdown.

def atexit_handler():
    print('atexit handler fired (Python interpreter finalisation)')

atexit.register(atexit_handler)

def do_sleep(duration):
    time.sleep(duration)

# Two request headers drive the application:
#
#   X-Failure-Mode  space-separated subset of:
#     application        raise before start_response, so the firing
#                        sequence is request_started ->
#                        request_exception -> request_finished
#                        (status=0, no response_started).
#     start_response_exc catch a synthetic exception and pass
#                        sys.exc_info() to start_response. The WSGI
#                        adapter forwards the tuple to subscribers
#                        as response_started.exception_info, which
#                        is None in every other mode.
#     yield              raise after the first yield, exercising
#                        mid-response failure. response_started has
#                        already fired by then.
#     close              raise in the generator's finally block,
#                        exercising the close-time failure path.
#
#   X-Sleep-Duration  float seconds to sleep before yielding.
#     Useful when issuing concurrent requests to observe multiple
#     in-flight entries in mod_wsgi.active_requests at the
#     response_started snapshot.

def application(environ, start_response):
    failure_mode = environ.get('HTTP_X_FAILURE_MODE', '')
    failure_mode = failure_mode.split()

    sleep_duration = environ.get('HTTP_X_SLEEP_DURATION', 0)
    sleep_duration = float(sleep_duration or 0)

    if 'application' in failure_mode:
        raise RuntimeError('application')

    # Application-side scratchpad write. mod_wsgi.request_data()
    # returns the same dict that subscribers see as the
    # request_data payload key, so this entry should be visible at
    # request_finished alongside the entries event_handler wrote
    # at request_started.

    mod_wsgi.request_data()['app_marker'] = 'set-by-application'

    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]

    if 'start_response_exc' in failure_mode:
        try:
            raise RuntimeError('start_response_exc')
        except RuntimeError:
            start_response(status, response_headers, sys.exc_info())
    else:
        start_response(status, response_headers)

    environ['wsgi.input'].read()

    if sleep_duration:
        do_sleep(sleep_duration)

    try:
        yield output

        if 'yield' in failure_mode:
            raise RuntimeError('yield')
    finally:
        if 'close' in failure_mode:
            raise RuntimeError('close')
