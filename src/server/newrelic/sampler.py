import threading
import atexit
import os
import sys
import json
import socket
import time
import math

try:
    import Queue as queue
except ImportError:
    import queue

import apache

SERVER_READY = '_'
SERVER_STARTING = 'S'
SERVER_BUSY_READ = 'R'
SERVER_BUSY_WRITE = 'W'
SERVER_BUST_KEEPALIVE = 'K'
SERVER_BUSY_LOG = 'L'
SERVER_BUSY_DNS = 'D'
SERVER_CLOSING = 'C'
SERVER_GRACEFUL = 'G'
SERVER_IDLE_KILL = 'I'
SERVER_DEAD = '.'

STATUS_FLAGS = {
    SERVER_READY: 'Ready',
    SERVER_STARTING: 'Starting',
    SERVER_BUSY_READ: 'Read',
    SERVER_BUSY_WRITE: 'Write',
    SERVER_BUST_KEEPALIVE: 'Keepalive',
    SERVER_BUSY_LOG: 'Logging',
    SERVER_BUSY_DNS: 'DNS lookup',
    SERVER_CLOSING: 'Closing',
    SERVER_GRACEFUL: 'Graceful',
    SERVER_IDLE_KILL: 'Dying',
    SERVER_DEAD: 'Dead'
}

class Sample(dict):

    def __init__(self, count=0, total=0.0, min=0.0, max=0.0,
            sum_of_squares=0.0):
        self.count = count
        self.total = total
        self.min = min
        self.max = max
        self.sum_of_squares = sum_of_squares

    def __setattr__(self, name, value):
        self[name] = value

    def __getattr__(self, name):
        return self[name]

    def merge_stats(self, other):
        self.total += other.total
        self.min = self.count and min(self.min, other.min) or other.min
        self.max = max(self.max, other.max)
        self.sum_of_squares += other.sum_of_squares
        self.count += other.count

    def merge_value(self, value):
        self.total += value
        self.min = self.count and min(self.min, value) or value
        self.max = max(self.max, value)
        self.sum_of_squares += value ** 2
        self.count += 1

class Samples(object):

    def __init__(self):
        self.samples = {}

    def __iter__(self):
        return iter(self.samples.items())

    def sample_name(self, name):
        return 'Component/' + name

    def _assign_value(self, value):
        if isinstance(value, Sample):
            sample = value
            self.samples[name] = sample
        else:
            sample = Sample()
            self.samples[name] = sample
            sample.merge_value(value)

        return sample

    def assign_value(self, value):
        name = self.sample_name(name)

        return self._assign_value(name)

    def _merge_value(self, name, value):
        sample = self.samples.get(name)

        if sample is None:
            sample = Sample()
            self.samples[name] = sample

        if isinstance(value, Sample):
            sample.merge_stats(value)
        else:
            sample.merge_value(value)

        return sample

    def merge_value(self, name, value):
        name = self.sample_name(name)

        return self._merge_value(name, value)

    def fetch_sample(self, name):
        name = self.sample_name(name)

        sample = self.samples.get(name)

        if sample is None:
            sample = Sample()
            self.samples[name] = sample

        return sample

    def merge_samples(self, samples):
        for name, sample in samples:
            self._merge_value(name, sample)

    def assign_samples(self, samples):
        for name, sample in samples:
            self._assign_value(name, sample)

    def clear_samples(self):
        self.samples.clear()

class Sampler(object):

    guid = 'au.com.dscpl.wsgi.mod_wsgi'
    version = '1.0.0'

    def __init__(self, interface, name):
        self.interface = interface
        self.name = name

        self.running = False
        self.lock = threading.Lock()

        self.period_start = 0
        self.access_count = 0
        self.bytes_served = 0

        self.request_samples = []

        self.metric_data = Samples()

        self.report_queue = queue.Queue()

        self.report_thread = threading.Thread(target=self.report_main_loop)
        self.report_thread.setDaemon(True)

        self.report_start = 0
        self.report_metrics = Samples()

        self.monitor_queue = queue.Queue()

        self.monitor_thread = threading.Thread(target=self.monitor_main_loop)
        self.monitor_thread.setDaemon(True)

        self.monitor_count = 0

    def upload_report(self, start, end, metrics):
        try:
            self.interface.send_metrics(self.name, self.guid, self.version,
                    end-start, metrics.samples)

        except self.interface.RetryDataForRequest:
            return True

        except Exception:
            pass

        return False

    def generate_request_metrics(self, harvest_data):
        metrics = Samples()

        # Chart as 'Throughput'.

        metrics.merge_value('Requests/Throughput[|requests]', 
                Sample(count=harvest_data['access_count'],
                total=harvest_data['access_count']))

        # Calculate from the set of sampled requests the average
        # and percentile metrics.

        requests = harvest_data['request_samples']

        if requests:
            for request in requests:
                # Chart as 'Average'.

                metrics.merge_value('Requests/Response Time[seconds|request]',
                        request['duration'])

            requests.sort(key=lambda e: e['duration'])

            total = sum([x['duration'] for x in requests])

            # Chart as 'Average'.

            metrics.merge_value('Requests/Percentiles/Average[seconds]',
                    total/len(requests))

            idx50 = int(0.50 * len(requests))
            metrics.merge_value('Requests/Percentiles/Median[seconds]',
                    requests[idx50]['duration'])

            idx95 = int(0.95 * len(requests))
            metrics.merge_value('Requests/Percentiles/95%[seconds]',
                    requests[idx95]['duration'])

            idx99 = int(0.99 * len(requests))
            metrics.merge_value('Requests/Percentiles/99%[seconds]',
                    requests[idx99]['duration'])

        # Chart as 'Rate'.

        metrics.merge_value('Requests/Bytes Served[bytes]',
                harvest_data['bytes_served'])

        return metrics

    def generate_process_metrics(self, harvest_data):
        metrics = Samples()

        # Chart as 'Count'. Round to Integer.

        metrics.merge_value('Processes/Instances[|processes]',
                Sample(count=math.ceil(float(
                harvest_data['processes_running']) /
                harvest_data['sample_count'])))

        metrics.merge_value('Processes/Lifecycle/Starting[|processes]',
                Sample(count=harvest_data['processes_started']))

        metrics.merge_value('Processes/Lifecycle/Stopping[|processes]',
                Sample(count=harvest_data['processes_stopped']))

        metrics.merge_value('Workers/Availability/Idle[|workers]',
                Sample(count=math.ceil(float(
                harvest_data['idle_workers']) /
                harvest_data['sample_count'])))
        metrics.merge_value('Workers/Availability/Busy[|workers]',
                Sample(count=math.ceil(float(
                harvest_data['busy_workers']) /
                harvest_data['sample_count'])))

        # Chart as 'Percentage'.

        metrics.merge_value('Workers/Utilization[server]',
                (float(harvest_data['busy_workers']) /
                harvest_data['sample_count']) / (
                harvest_data['server_limit']*harvest_data['thread_limit']))

        total = 0
        for value in harvest_data['worker_status'].values():
            value = float(value)/harvest_data['sample_count']
            total += value

        if total:
            for key, value in harvest_data['worker_status'].items():
                if key != SERVER_DEAD and value != 0:
                   label = STATUS_FLAGS.get(key, 'Unknown')

                    # Chart as 'Average'. Round to Integer.

                   value = float(value)/harvest_data['sample_count']

                   metrics.merge_value('Workers/Status/%s[workers]' %
                       label, (value/total)*total)

        return metrics

    def report_main_loop(self):
        # We need a set of cached metrics for the case where
        # we fail in uploading the metric data and need to
        # retain it for the next attempt to upload data.

        retries = 0
        retained_start = 0
        retained = Samples()

        # We simply wait to be passed the metric data to be
        # reported for the current sample period.

        while True:
            harvest_data = self.report_queue.get()

            # If samples is None then we are being told to
            # exit as the process is being shutdown. Otherwise
            # we should be passed the cumulative metric data
            # and the set of sampled requests.

            if harvest_data is None:
                return

            start = harvest_data['period_start']
            end = harvest_data['period_end']

            metrics = harvest_data['metrics']

            # Add metric to track how many Apache server instances
            # are reporting for each sample period.

            # Chart as 'Count'. Round to Integer.

            metrics.merge_value('Server/Instances[|servers]', 0)

            # Generate percentiles metrics for request samples.

            metrics.merge_samples(self.generate_request_metrics(harvest_data))
            metrics.merge_samples(self.generate_process_metrics(harvest_data))

            # If we had metrics from a previous reporting period
            # because we couldn't upload the metric data, we need
            # to merge the data from the current reporting period
            # with that for the previous period.

            if retained.samples:
                start = retained_start
                retained.merge_samples(metrics)
                metrics = retained

            # Now attempt to upload the metric data.

            retry = self.upload_report(start, end, metrics)

            # If a failure occurred but failure type was such that we
            # could try again to upload the data, then retain them. If
            # have two many failed attempts though we give up.

            if retry:
                retries += 1

                if retries == 5:
                    retries = 0

                else:
                    retained = metrics

            else:
                retries = 0

            if retries == 0:
                retained_start = 0
                retained.clear_samples()

            else:
                retained_start = start
                retained = metrics

    def generate_scoreboard(self, sample_start=None):
        busy_workers = 0
        idle_workers = 0
        access_count = 0
        bytes_served = 0

        active_processes = 0

        scoreboard = apache.scoreboard()

        if sample_start is None:
            sample_start = scoreboard['current_time']

        scoreboard['request_samples'] = request_samples = []

        for process in scoreboard['processes']:
            process['active_workers'] = 0

            for worker in process['workers']:
                status = worker['status']

                if not process['quiescing'] and process['pid']:
                    if (status == SERVER_READY and process['generation'] ==
                            scoreboard['running_generation']):

                        process['active_workers'] += 1
                        idle_workers += 1

                    elif status not in (SERVER_DEAD, SERVER_STARTING,
                            SERVER_IDLE_KILL):

                        process['active_workers'] += 1
                        busy_workers += 1

                count = worker['access_count']

                if count or status not in (SERVER_READY, SERVER_DEAD):
                    access_count += count
                    bytes_served += worker['bytes_served']

                current_time = scoreboard['current_time']

                start_time = worker['start_time']
                stop_time = worker['stop_time']

                if (stop_time > start_time and sample_start < stop_time
                        and stop_time <= current_time):

                    duration = stop_time - start_time
                    thread_num = worker['thread_num']

                    request_samples.append(dict(start_time=start_time,
                            duration=duration, thread_num=thread_num))

            if process['active_workers']:
                active_processes += 1

        scoreboard['busy_workers'] = busy_workers
        scoreboard['idle_workers'] = idle_workers
        scoreboard['access_count'] = access_count
        scoreboard['bytes_served'] = bytes_served

        scoreboard['active_processes'] = active_processes

        return scoreboard

    def record_process_statistics(self, scoreboard, harvest_data):
        current_active_processes = scoreboard['active_processes']
        previous_active_processes = harvest_data['active_processes']

        harvest_data['active_processes'] = current_active_processes
        harvest_data['processes_running'] += current_active_processes

        if current_active_processes > previous_active_processes:
            harvest_data['processes_started'] += (current_active_processes -
                    previous_active_processes)

        elif current_active_processes < previous_active_processes:
            harvest_data['processes_stopped'] += (previous_active_processes -
                    current_active_processes)

        harvest_data['idle_workers'] += scoreboard['idle_workers']
        harvest_data['busy_workers'] += scoreboard['busy_workers']

        for process in scoreboard['processes']:
           for worker in process['workers']:
               harvest_data['worker_status'][worker['status']] += 1

    def monitor_main_loop(self):
        scoreboard = self.generate_scoreboard()

        harvest_start = scoreboard['current_time']
        sample_start = harvest_start
        sample_duration = 0.0

        access_count = scoreboard['access_count']
        bytes_served = scoreboard['bytes_served']

        harvest_data = {}

        harvest_data['sample_count'] = 0
        harvest_data['period_start'] = harvest_start

        harvest_data['metrics'] = Samples()

        harvest_data['request_samples'] = []

        harvest_data['active_processes'] = 0

        harvest_data['processes_running'] = 0
        harvest_data['processes_started'] = 0
        harvest_data['processes_stopped'] = 0

        harvest_data['idle_workers'] = 0
        harvest_data['busy_workers'] = 0

        harvest_data['server_limit'] = scoreboard['server_limit']
        harvest_data['thread_limit'] = scoreboard['thread_limit']

        harvest_data['worker_status'] = {}

        for status in STATUS_FLAGS.keys():
            harvest_data['worker_status'][status] = 0

        harvest_data['access_count'] = 0
        harvest_data['bytes_served'] = 0

        # Chart as 'Count'. Round to Integer.

        harvest_data['metrics'].merge_value('Server/Restarts[|servers]', 0)

        start = time.time()
        end = start + 60.0

        while True:
            try:
                # We want to collect metrics on a regular second
                # interval so we need to align the timeout value.

                now = time.time()
                start += 1.0
                timeout = start - now

                return self.monitor_queue.get(timeout=timeout)

            except queue.Empty:
                pass

            harvest_data['sample_count'] += 1

            scoreboard = self.generate_scoreboard(sample_start)

            harvest_end = scoreboard['current_time']
            sample_end = harvest_end

            sample_duration = sample_end - sample_start

            self.record_process_statistics(scoreboard, harvest_data)

            harvest_data['request_samples'].extend(
                    scoreboard['request_samples'])

            access_count_delta = scoreboard['access_count']
            access_count_delta -= access_count
            access_count = scoreboard['access_count']

            harvest_data['access_count'] += access_count_delta

            bytes_served_delta = scoreboard['bytes_served']
            bytes_served_delta -= bytes_served
            bytes_served = scoreboard['bytes_served']

            harvest_data['bytes_served'] += bytes_served_delta

            now = time.time()

            if now >= end:
                harvest_data['period_end'] = harvest_end

                self.report_queue.put(harvest_data)

                harvest_start = harvest_end
                end += 60.0

                _harvest_data = {}

                _harvest_data['sample_count'] = 0
                _harvest_data['period_start'] = harvest_start

                _harvest_data['metrics'] = Samples()

                _harvest_data['request_samples'] = []

                _harvest_data['active_processes'] = (
                        harvest_data['active_processes'])

                _harvest_data['processes_running'] = 0
                _harvest_data['processes_started'] = 0
                _harvest_data['processes_stopped'] = 0

                _harvest_data['idle_workers'] = 0
                _harvest_data['busy_workers'] = 0

                _harvest_data['server_limit'] = scoreboard['server_limit']
                _harvest_data['thread_limit'] = scoreboard['thread_limit']

                _harvest_data['worker_status'] = {}

                for status in STATUS_FLAGS.keys():
                    _harvest_data['worker_status'][status] = 0

                _harvest_data['access_count'] = 0
                _harvest_data['bytes_served'] = 0

                harvest_data = _harvest_data

            sample_start = sample_end

    def terminate(self):
        try:
            self.report_queue.put(None)
            self.monitor_queue.put(None)
        except Exception:
            pass

        self.monitor_thread.join()
        self.report_thread.join()

    def start(self):
        with self.lock:
            if not self.running:
                self.running = True
                atexit.register(self.terminate)
                self.monitor_thread.start()
                self.report_thread.start()
