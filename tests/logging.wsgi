import logging
import warnings

# Apache already decorates every error-log entry with a timestamp,
# log level, pid/tid, and (for in-request emissions) the remote and
# script tags. The Python logging format here omits the timestamp
# and just carries the Python level, logger name, and message so
# the resulting log line is not double-timestamped. Iterate on the
# format choice once the routing behaviour is understood.

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s %(name)s %(message)s',
)

logger = logging.getLogger('wsgi-app')

# A second logger with its own elevated level. Apache's LogLevel
# does not filter Python application output, so Python-side level
# control is the only lever. Setting quiet_logger to WARNING means
# its DEBUG and INFO emissions are dropped before reaching the
# handler chain, even though the root logger is configured at
# DEBUG; nothing about Apache's configuration affects this.

quiet_logger = logging.getLogger('wsgi-app.quiet')
quiet_logger.setLevel(logging.WARNING)

# An orphan logger with propagation disabled and no handler
# attached. Records have nowhere to go via the normal chain, so
# Python's logging.lastResort handler is used (a StreamHandler at
# WARNING writing to sys.stderr, no level/name in the format).
# Worth seeing what this looks like as a worked example of what
# happens when an application skips basicConfig entirely: the
# log line carries the message body but loses the level prefix
# and logger name, and DEBUG / INFO are silently dropped.

orphan_logger = logging.getLogger('wsgi-app.orphan')
orphan_logger.propagate = False

# Route Python's warnings.warn() output through the logging
# system. After captureWarnings(True) any warnings.warn(...)
# lands on the py.warnings logger at WARNING level (and therefore
# picks up the same format/handler chain as application logging)
# instead of going directly to sys.stderr via warnings.showwarning.
# simplefilter('always') defeats the default Python filter that
# suppresses DeprecationWarning outside __main__ so both
# categories below surface in the log. Note that simplefilter
# replaces the entire Python warnings filter chain, including any
# entries WSGIPythonWarnings (or mod_wsgi-express --python-warnings)
# installed at interpreter startup. This file is about routing
# fired warnings into the logging system, not about filtering;
# see tests/warnings.wsgi for the filter-chain probe.

warnings.simplefilter('always')
logging.captureWarnings(True)

logger.debug('module-scope logger.debug')
logger.info('module-scope logger.info')
logger.warning('module-scope logger.warning')
logger.error('module-scope logger.error')
logger.critical('module-scope logger.critical')

quiet_logger.debug('module-scope quiet_logger.debug (filtered)')
quiet_logger.info('module-scope quiet_logger.info (filtered)')
quiet_logger.warning('module-scope quiet_logger.warning')
quiet_logger.error('module-scope quiet_logger.error')
quiet_logger.critical('module-scope quiet_logger.critical')

orphan_logger.debug('module-scope orphan_logger.debug (filtered)')
orphan_logger.info('module-scope orphan_logger.info (filtered)')
orphan_logger.warning('module-scope orphan_logger.warning (bare)')
orphan_logger.error('module-scope orphan_logger.error (bare)')
orphan_logger.critical('module-scope orphan_logger.critical (bare)')

warnings.warn('module-scope UserWarning via warnings.warn', UserWarning)
warnings.warn('module-scope DeprecationWarning via warnings.warn',
        DeprecationWarning)

def application(environ, start_response):
    logger.debug('request logger.debug')
    logger.info('request logger.info')
    logger.warning('request logger.warning')
    logger.error('request logger.error')
    logger.critical('request logger.critical')

    quiet_logger.debug('request quiet_logger.debug (filtered)')
    quiet_logger.info('request quiet_logger.info (filtered)')
    quiet_logger.warning('request quiet_logger.warning')
    quiet_logger.error('request quiet_logger.error')
    quiet_logger.critical('request quiet_logger.critical')

    orphan_logger.debug('request orphan_logger.debug (filtered)')
    orphan_logger.info('request orphan_logger.info (filtered)')
    orphan_logger.warning('request orphan_logger.warning (bare)')
    orphan_logger.error('request orphan_logger.error (bare)')
    orphan_logger.critical('request orphan_logger.critical (bare)')

    warnings.warn('request UserWarning via warnings.warn', UserWarning)
    warnings.warn('request DeprecationWarning via warnings.warn',
            DeprecationWarning)

    try:
        raise RuntimeError('illustrative failure')
    except RuntimeError:
        logger.exception('request logger.exception')

    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]
