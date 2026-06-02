/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2026 GRAHAM DUMPLETON
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* ------------------------------------------------------------------------- */

#include "wsgi_input.h"

#include "wsgi_daemon.h"
#include "wsgi_metrics.h"
#include "wsgi_module.h"

/* ------------------------------------------------------------------------- */

InputObject *newInputObject(request_rec *r, int ignore_activity)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    InputObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the Input heap type out of its state.
     * Returns NULL with a clear error if the module is not in
     * sys.modules or its state has not been initialised; either
     * indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Input_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Input type not initialised for the current "
                        "interpreter; newInputObject() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Input_Type;

    self = (InputObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    self->r = r;
    self->init = 0;
    self->done = 0;

    self->buffer = NULL;
    self->size = 0;
    self->offset = 0;
    self->length = 0;

    self->bb = NULL;

    self->seen_eos = 0;
    self->seen_error = 0;

    self->bytes = 0;
    self->reads = 0;
    self->time = 0;

    self->ignore_activity = ignore_activity;

    return self;
}

/*
 * Heap-type destructor. Frees the residual readline buffer (if
 * any), then releases the instance memory via the type's tp_free
 * and decrements the type's refcount (every heap-type instance
 * owns a reference to its type).
 *
 * Note that the bucket brigade and request_rec back-pointer are
 * released by Input_finish at end of request, not here. Dealloc
 * runs whenever the last Python reference goes away, which may
 * be long after the request has completed.
 */

static void Input_dealloc(InputObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    if (self->buffer)
        free(self->buffer);

    tp->tp_free(self);
    Py_DECREF(tp);
}

void Input_finish(InputObject *self)
{
    if (self->bb)
    {
        WSGI_BEGIN_ALLOW_THREADS
        apr_brigade_destroy(self->bb);
        WSGI_END_ALLOW_THREADS

        self->bb = NULL;
    }

    self->r = NULL;
}

static PyObject *Input_close(InputObject *self, PyObject *args)
{
    /*
     * Nothing to close here. The underlying bucket brigade lives in
     * the request pool and is cleaned up by Input_finish when the
     * request completes. The only thing we want to catch is code
     * that reaches into wsgi.input after the request has already
     * finished (for example via a stashed environ reference hit by
     * GC, or post-commit cleanup in a web framework), so surface a
     * RuntimeError in that case rather than silently succeeding.
     */

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "close() called on wsgi.input after request "
                        "completed");
        return NULL;
    }

    Py_RETURN_NONE;
}

static apr_int64_t Input_read_from_input(InputObject *self, char *buffer,
                                         apr_size_t bufsiz)
{
    request_rec *r = self->r;
    apr_bucket_brigade *bb = self->bb;

    apr_status_t rv;

    apr_status_t error_status = 0;
    const char *error_message = NULL;

    apr_time_t start = 0;
    apr_time_t finish = 0;

    /* If have already seen end of input, return an empty string. */

    if (self->seen_eos)
        return 0;

    /* If have already encountered an error, then raise a new error. */

    if (self->seen_error)
    {
        PyErr_SetString(PyExc_IOError, "mod_wsgi request data read "
                                       "error: input is already in error state");

        return -1;
    }

    /*
     * When reaading the request content we will be saying that we
     * should block if there is no input data available at that
     * point but not all data has been exhausted. We therefore need
     * to ensure that we do not cause Python as a whole to block by
     * releasing the GIL, but also must remember to reacquire the GIL
     * when we exit.
     */

    WSGI_BEGIN_ALLOW_THREADS

    start = apr_time_now();

    self->reads += 1;

    /*
     * Create the bucket brigade the first time it is required and
     * save it against the input object. We need to make sure we
     * perform a cleanup, but not destroy, the bucket brigade each
     * time we exit this function.
     */

    if (!bb)
    {
        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        if (bb == NULL)
        {
            r->connection->keepalive = AP_CONN_CLOSE;
            error_message = "Unable to create bucket brigade";
            goto finally;
        }

        self->bb = bb;
    }

    /* Force the required amount of input to be read. */

    rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                        APR_BLOCK_READ, bufsiz);

    if (rv != APR_SUCCESS)
    {
        /*
         * If we actually fail here, we want to just return and
         * stop trying to read data from the client. The HTTP_IN
         * input filter is a bit of a pain here as it can return
         * EAGAIN in various strange situations where it isn't
         * believed that it means to retry, but that it is still
         * a permanent failure. This can include timeouts and
         * errors in chunked encoding format. To avoid a message
         * of 'Resource temporarily unavailable' which could be
         * confusing, replace it with a generic message that the
         * connection was terminated.
         */

        r->connection->keepalive = AP_CONN_CLOSE;

        if (APR_STATUS_IS_EAGAIN(rv))
            error_message = "Connection was terminated";
        else
            error_status = rv;

        goto finally;
    }

    /*
     * If this fails, it means that a filter is written incorrectly and
     * that it needs to learn how to properly handle APR_BLOCK_READ
     * requests by returning data when requested.
     */

    AP_DEBUG_ASSERT(!APR_BRIGADE_EMPTY(bb));

    /*
     * Check to see if EOS terminates the brigade. If so, we remember
     * this to avoid any attempts to read more data in future calls.
     */

    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb)))
        self->seen_eos = 1;

    /* Now extract the actual data from the bucket brigade. */

    rv = apr_brigade_flatten(bb, buffer, &bufsiz);

    if (rv != APR_SUCCESS)
    {
        error_status = rv;
        goto finally;
    }

finally:
    /*
     * We must always cleanup up, not destroy, the brigade after
     * each call.
     */

    if (bb)
        apr_brigade_cleanup(bb);

    finish = apr_time_now();

    if (finish > start)
        self->time += (finish - start);

    /* Make sure we reacquire the GIL when all done. */

    WSGI_END_ALLOW_THREADS

    /*
     * Set any Python exception when an error has occurred and
     * remember there was an error so can flag on subsequent
     * reads that already in an error state.
     */

    if (error_status)
    {
        char status_buffer[512];

        error_message = apr_psprintf(r->pool, "mod_wsgi request "
                                              "data read error: %s",
                                     apr_strerror(error_status,
                                                  status_buffer, sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);

        self->seen_error = 1;

        return -1;
    }
    else if (error_message)
    {
        error_message = apr_psprintf(r->pool, "mod_wsgi request "
                                              "data read error: %s",
                                     error_message);

        PyErr_SetString(PyExc_IOError, error_message);

        self->seen_error = 1;

        return -1;
    }

    /*
     * Finally return the amount of data that was read. This will be
     * zero if all data has been consumed.
     */

    return bufsiz;
}

static PyObject *Input_read(InputObject *self, PyObject *args)
{
    Py_ssize_t size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    Py_ssize_t length = 0;
    int init = 0;

    Py_ssize_t n;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "read() called on wsgi.input after request "
                        "completed");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|n:read", &size))
        return NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
    }
#endif

    if (self->seen_error)
    {
        PyErr_SetString(PyExc_IOError, "mod_wsgi request data read "
                                       "error: input is already in error state");

        return NULL;
    }

    init = self->init;

    if (!self->init)
        self->init = 1;

    /* No point continuing if no more data to be consumed. */

    if (self->done && self->length == 0)
        return PyBytes_FromString("");

    /*
     * If requested size is zero bytes, then still need to pass
     * this through to Apache input filters so that any
     * 100-continue response is triggered. Only do this if very
     * first attempt to read data. Note that this will cause an
     * assertion failure in HTTP_IN input filter when Apache
     * maintainer mode is enabled. It is arguable that the
     * assertion check, which prohibits a zero length read,
     * shouldn't exist, as why should a zero length read be not
     * allowed if input filter processing still works when it
     * does occur.
     */

    if (size == 0)
    {
        if (!init)
        {
            char dummy[1];

            n = Input_read_from_input(self, dummy, 0);

            if (n == -1)
                return NULL;
        }

        return PyBytes_FromString("");
    }

    /*
     * First deal with case where size has been specified. After
     * that deal with case where expected that all remaining
     * data is to be read in and returned as one string.
     */

    if (size > 0)
    {
        /* Allocate string of the exact size required. */

        result = PyBytes_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyBytes_AS_STRING((PyBytesObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length)
        {
            if (size >= self->length)
            {
                length = self->length;
                memcpy(buffer, self->buffer + self->offset, length);
                self->offset = 0;
                self->length = 0;
            }
            else
            {
                length = size;
                memcpy(buffer, self->buffer + self->offset, length);
                self->offset += length;
                self->length -= length;
            }
        }

        /* If all data residual buffer consumed then free it. */

        if (!self->length)
        {
            free(self->buffer);
            self->buffer = NULL;
        }

        /* Read in remaining data required to achieve size. */

        if (length < size)
        {
            while (length != size)
            {
                n = Input_read_from_input(self, buffer + length, size - length);

                if (n == -1)
                {
                    Py_DECREF(result);
                    return NULL;
                }
                else if (n == 0)
                {
                    /* Have exhausted all the available input data. */

                    self->done = 1;
                    break;
                }

                length += n;
            }

            /*
             * Resize the final string. If the size reduction is
             * by more than 25% of the string size, then Python
             * will allocate a new block of memory and copy the
             * data into it.
             */

            if (length != size)
            {
                if (_PyBytes_Resize(&result, length))
                {
                    self->seen_error = 1;
                    return NULL;
                }
            }
        }
    }
    else
    {
        /*
         * Here we are going to try and read in all the
         * remaining data. First we have to allocate a suitably
         * large string, but we can't fully trust the amount
         * that the request structure says is remaining based on
         * the original content length though, as an input
         * filter can insert/remove data from the input stream
         * thereby invalidating the original content length.
         * What we do is allow for an extra 25% above what we
         * have already buffered and what the request structure
         * says is remaining. A value of 25% has been chosen so
         * as to match best how Python handles resizing of
         * strings. Note that even though we do this and allow
         * all available content, strictly speaking the WSGI
         * specification says we should only read up until content
         * length. This though is because the WSGI specification
         * is deficient in dealing with the concept of mutating
         * input filters. Since read() with no argument is also
         * not allowed by WSGI specification implement it in the
         * way which is most logical and ensure that input data
         * is not truncated.
         */

        if (self->buffer)
        {
            size = self->length;
            size = size + (size >> 2);

            if (size < HUGE_STRING_LEN)
                size = HUGE_STRING_LEN;
        }
        else
            size = HUGE_STRING_LEN;

        /* Allocate string of the estimated size. */

        result = PyBytes_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyBytes_AS_STRING((PyBytesObject *)result);

        /*
         * Copy any residual data from use of readline(). The
         * residual should always be less in size than the
         * string we have allocated to hold it, so can consume
         * all of it.
         */

        if (self->buffer && self->length)
        {
            length = self->length;
            memcpy(buffer, self->buffer + self->offset, length);
            self->offset = 0;
            self->length = 0;

            free(self->buffer);
            self->buffer = NULL;
        }

        /* Now make first attempt at reading remaining data. */

        n = Input_read_from_input(self, buffer + length, size - length);

        if (n == -1)
        {
            Py_DECREF(result);
            return NULL;
        }
        else if (n == 0)
        {
            /* Have exhausted all the available input data. */

            self->done = 1;
        }

        length += n;

        /*
         * Don't just assume that all data has been read if
         * amount read was less than that requested. Still must
         * perform a read which returns that no more data found.
         */

        while (!self->done)
        {
            if (length == size)
            {
                /* Increase the size of the string by 25%. */

                size = size + (size >> 2);

                if (_PyBytes_Resize(&result, size))
                {
                    self->seen_error = 1;
                    return NULL;
                }

                buffer = PyBytes_AS_STRING((PyBytesObject *)result);
            }

            /* Now make succesive attempt at reading data. */

            n = Input_read_from_input(self, buffer + length, size - length);

            if (n == -1)
            {
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0)
            {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }

            length += n;
        }

        /*
         * Resize the final string. If the size reduction is by
         * more than 25% of the string size, then Python will
         * allocate a new block of memory and copy the data into
         * it.
         */

        if (length != size)
        {
            if (_PyBytes_Resize(&result, length))
            {
                self->seen_error = 1;
                return NULL;
            }
        }
    }

    self->bytes += length;

    return result;
}

static PyObject *Input_readline(InputObject *self, PyObject *args)
{
    Py_ssize_t size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    Py_ssize_t length = 0;

    Py_ssize_t n;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "readline() called on wsgi.input after request "
                        "completed");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|n:readline", &size))
        return NULL;

    if (self->seen_error)
    {
        PyErr_SetString(PyExc_IOError, "mod_wsgi request data read "
                                       "error: input is already in error state");

        return NULL;
    }

    if (!self->init)
        self->init = 1;

    /*
     * No point continuing if requested size is zero or if no
     * more data to read and no buffered data.
     */

    if ((self->done && self->length == 0) || size == 0)
        return PyBytes_FromString("");

    /*
     * First deal with case where size has been specified. After
     * that deal with case where expected that a complete line
     * is returned regardless of the size.
     */

    if (size > 0)
    {
        /* Allocate string of the exact size required. */

        result = PyBytes_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyBytes_AS_STRING((PyBytesObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length)
        {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size)
            {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length)
            {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data required to achieve size. Note
         * that can't just return whatever the first read might
         * have returned if no EOL encountered as must return
         * exactly the required size if no EOL unless that would
         * have exhausted all input.
         */

        while ((!length || buffer[length - 1] != '\n') &&
               !self->done && length < size)
        {

            char *p = NULL;
            char *q = NULL;

            n = Input_read_from_input(self, buffer + length, size - length);

            if (n == -1)
            {
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0)
            {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else
            {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q)
                {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q)
                {
                    /*
                     * TODO: self->size looks like it could be a
                     * local. It is only used here (and at the
                     * equivalent residual-stash site in the no-size
                     * branch below) as the immediate malloc length
                     * and memcpy length, and self->length is
                     * assigned the same value on the next line.
                     * Leaving it on the struct until the original
                     * intent is confirmed.
                     */
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);

                    if (!self->buffer)
                    {
                        PyErr_NoMemory();
                        Py_DECREF(result);
                        self->seen_error = 1;
                        return NULL;
                    }

                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is
         * by more than 25% of the string size, then Python
         * will allocate a new block of memory and copy the
         * data into it.
         */

        if (length != size)
        {
            if (_PyBytes_Resize(&result, length))
            {
                self->seen_error = 1;
                return NULL;
            }
        }
    }
    else
    {
        /*
         * Here we have to read in a line but where we have no
         * idea how long it may be. What we can do first is if
         * we have any residual data from a previous read
         * operation, see if it contains an EOL. This means we
         * have to do a search, but this is likely going to be
         * better than having to resize and copy memory later on.
         */

        if (self->buffer && self->length)
        {
            const char *p = NULL;
            const char *q = NULL;

            p = self->buffer + self->offset;
            q = memchr(p, '\n', self->length);

            if (q)
                size = q - p;
        }

        /*
         * If residual data buffer didn't contain an EOL, all we
         * can do is allocate a reasonably sized string and if
         * that isn't big enough keep increasing it in size. For
         * this we will start out with a buffer 25% greater in
         * size than what is stored in the residual data buffer
         * or one the same size as Apache string size, whichever
         * is greater.
         */

        if (self->buffer && size < 0)
        {
            size = self->length;
            size = size + (size >> 2);
        }

        if (size < HUGE_STRING_LEN)
            size = HUGE_STRING_LEN;

        /* Allocate string of the initial size. */

        result = PyBytes_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyBytes_AS_STRING((PyBytesObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length)
        {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size)
            {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length)
            {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data until find an EOL, or until all
         * data has been consumed.
         */

        while ((!length || buffer[length - 1] != '\n') && !self->done)
        {

            char *p = NULL;
            char *q = NULL;

            n = Input_read_from_input(self, buffer + length, size - length);

            if (n == -1)
            {
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0)
            {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else
            {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q)
                {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q)
                {
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);

                    if (!self->buffer)
                    {
                        PyErr_NoMemory();
                        Py_DECREF(result);
                        self->seen_error = 1;
                        return NULL;
                    }

                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }

                if (buffer[length - 1] != '\n' && length == size)
                {
                    /* Increase size of string and keep going. */

                    size = size + (size >> 2);

                    if (_PyBytes_Resize(&result, size))
                    {
                        self->seen_error = 1;
                        return NULL;
                    }

                    buffer = PyBytes_AS_STRING((PyBytesObject *)result);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is by
         * more than 25% of the string size, then Python will
         * allocate a new block of memory and copy the data into
         * it.
         */

        if (length != size)
        {
            if (_PyBytes_Resize(&result, length))
            {
                self->seen_error = 1;
                return NULL;
            }
        }
    }

    self->bytes += length;

    return result;
}

static PyObject *Input_readlines(InputObject *self, PyObject *args)
{
    Py_ssize_t hint = 0;
    Py_ssize_t length = 0;

    PyObject *result = NULL;
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "readlines() called on wsgi.input after request "
                        "completed");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|n:readlines", &hint))
        return NULL;

    result = PyList_New(0);
    if (!result)
        return NULL;

    rlargs = PyTuple_New(0);
    if (!rlargs)
    {
        Py_DECREF(result);
        return NULL;
    }

    while (1)
    {
        Py_ssize_t n;

        if (!(line = Input_readline(self, rlargs)))
        {
            Py_CLEAR(result);
            break;
        }

        if ((n = PyBytes_Size(line)) == 0)
        {
            Py_DECREF(line);
            break;
        }

        if (PyList_Append(result, line) == -1)
        {
            Py_DECREF(line);
            Py_CLEAR(result);
            break;
        }

        Py_DECREF(line);

        length += n;
        if (hint > 0 && length >= hint)
            break;
    }

    Py_DECREF(rlargs);

    return result;
}

static PyMethodDef Input_methods[] = {
    {"close", (PyCFunction)Input_close, METH_NOARGS, 0},
    {"read", (PyCFunction)Input_read, METH_VARARGS, 0},
    {"readline", (PyCFunction)Input_readline, METH_VARARGS, 0},
    {"readlines", (PyCFunction)Input_readlines, METH_VARARGS, 0},
    {NULL, NULL}};

static PyObject *Input_iter(InputObject *self)
{
    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "iteration of wsgi.input attempted after request "
                        "completed");
        return NULL;
    }

    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *Input_iternext(InputObject *self)
{
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "iteration of wsgi.input attempted after request "
                        "completed");
        return NULL;
    }

    rlargs = PyTuple_New(0);

    if (!rlargs)
        return NULL;

    line = Input_readline(self, rlargs);

    Py_DECREF(rlargs);

    if (!line)
        return NULL;

    if (PyBytes_GET_SIZE(line) == 0)
    {
        PyErr_SetObject(PyExc_StopIteration, Py_None);
        Py_DECREF(line);
        return NULL;
    }

    return line;
}

/*
 * PyType_Spec for the Input heap type. The slots with non-default
 * behaviour are tp_dealloc (frees the residual readline buffer),
 * tp_iter / tp_iternext (line-by-line iteration), and tp_methods
 * (read / readline / readlines / close); everything else falls
 * back to the framework defaults.
 *
 * tp_name is "mod_wsgi.Input" so error messages and repr() output
 * identify where the type comes from. The type is not exposed as
 * a module attribute; instances are produced by newInputObject
 * from C and handed to the WSGI application as
 * environ["wsgi.input"].
 */

static PyType_Slot Input_slots[] = {
    {Py_tp_dealloc, Input_dealloc},
    {Py_tp_iter, Input_iter},
    {Py_tp_iternext, Input_iternext},
    {Py_tp_methods, Input_methods},
    {0, NULL},
};

static PyType_Spec Input_spec = {
    .name = "mod_wsgi.Input",
    .basicsize = sizeof(InputObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = Input_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_input_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &Input_spec, NULL);
    if (!type)
        return -1;

    state->Input_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
