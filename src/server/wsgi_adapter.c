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

#include "wsgi_adapter.h"

#include "wsgi_buckets.h"
#include "wsgi_convert.h"
#include "wsgi_daemon.h"
#include "wsgi_interp.h"
#include "wsgi_logger.h"
#include "wsgi_metrics.h"
#include "wsgi_stream.h"
#include "wsgi_thread.h"
#include "wsgi_validate.h"
#include "wsgi_version.h"

/* ------------------------------------------------------------------------- */

static InputObject *newInputObject(request_rec *r, int ignore_activity)
{
    InputObject *self;

    self = PyObject_New(InputObject, &Input_Type);
    if (self == NULL)
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

static void Input_dealloc(InputObject *self)
{
    if (self->buffer)
        free(self->buffer);

    PyObject_Del(self);
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
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
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                                       "error: Input is already in error state.");

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

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi request "
                                              "data read error: %s.",
                                     apr_strerror(error_status,
                                                  status_buffer, sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);

        self->seen_error = 1;

        return -1;
    }
    else if (error_message)
    {
        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi request "
                                              "data read error: %s.",
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|n:read", &size))
        return NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    if (self->seen_error)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                                       "error: Input is already in error state.");

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
                    return NULL;
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
                    return NULL;

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
                return NULL;
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|n:readline", &size))
        return NULL;

    if (self->seen_error)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                                       "error: Input is already in error state.");

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
                return NULL;
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
                        return NULL;

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
                return NULL;
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
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
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
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

PyTypeObject Input_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.Input", /*tp_name*/
    sizeof(InputObject),                             /*tp_basicsize*/
    0,                                               /*tp_itemsize*/
    /* methods */
    (destructor)Input_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash*/
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
#if defined(Py_TPFLAGS_HAVE_ITER)
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
#else
    Py_TPFLAGS_DEFAULT, /*tp_flags*/
#endif
    0,                            /*tp_doc*/
    0,                            /*tp_traverse*/
    0,                            /*tp_clear*/
    0,                            /*tp_richcompare*/
    0,                            /*tp_weaklistoffset*/
    (getiterfunc)Input_iter,      /*tp_iter*/
    (iternextfunc)Input_iternext, /*tp_iternext*/
    Input_methods,                /*tp_methods*/
    0,                            /*tp_members*/
    0,                            /*tp_getset*/
    0,                            /*tp_base*/
    0,                            /*tp_dict*/
    0,                            /*tp_descr_get*/
    0,                            /*tp_descr_set*/
    0,                            /*tp_dictoffset*/
    0,                            /*tp_init*/
    0,                            /*tp_alloc*/
    0,                            /*tp_new*/
    0,                            /*tp_free*/
    0,                            /*tp_is_gc*/
};

AdapterObject *newAdapterObject(request_rec *r)
{
    AdapterObject *self;

    self = PyObject_New(AdapterObject, &Adapter_Type);
    if (self == NULL)
        return NULL;

    self->result = HTTP_INTERNAL_SERVER_ERROR;

    self->r = r;

    self->bb = NULL;

    self->config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                             &wsgi_module);

    self->status = HTTP_INTERNAL_SERVER_ERROR;
    self->status_line = NULL;
    self->headers = NULL;
    self->sequence = NULL;

    self->content_length_set = 0;
    self->content_length = 0;
    self->output_length = 0;
    self->output_writes = 0;

    self->output_time = 0;

    self->input = NULL;
    self->log_buffer = NULL;
    self->log = NULL;

    self->input = newInputObject(r, self->config->ignore_activity);

    if (!self->input)
    {
        Py_DECREF(self);
        return NULL;
    }

    self->log_buffer = newLogBufferObject(r, APLOG_ERR, "<wsgi.errors>", 0);

    if (!self->log_buffer)
    {
        Py_DECREF(self);
        return NULL;
    }

    self->log = newLogWrapperObject(self->log_buffer);

    if (!self->log)
    {
        Py_DECREF(self);
        return NULL;
    }

    return self;
}

static void Adapter_dealloc(AdapterObject *self)
{
    Py_XDECREF(self->headers);
    Py_XDECREF(self->sequence);

    Py_XDECREF(self->input);

    Py_XDECREF(self->log_buffer);
    Py_XDECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Adapter_start_response(AdapterObject *self, PyObject *args)
{
    PyObject *result = NULL;

    PyObject *status_line = NULL;
    PyObject *headers = NULL;
    PyObject *exc_info = Py_None;

    PyObject *status_line_as_bytes = NULL;
    PyObject *headers_as_bytes = NULL;

    PyObject *event = NULL;
    PyObject *item = NULL;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "OO!|O:start_response",
                          &status_line, &PyList_Type, &headers, &exc_info))
    {
        return NULL;
    }

    if (exc_info != Py_None && !PyTuple_Check(exc_info))
    {
        PyErr_SetString(PyExc_RuntimeError, "exception info must be a tuple");
        return NULL;
    }

    if (exc_info != Py_None)
    {
        if (self->status_line && !self->headers)
        {
            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (!PyArg_ParseTuple(exc_info, "OOO", &type,
                                  &value, &traceback))
            {
                return NULL;
            }

            Py_INCREF(type);
            Py_INCREF(value);
            Py_INCREF(traceback);

            PyErr_Restore(type, value, traceback);

            return NULL;
        }
    }
    else if (self->status_line && !self->headers)
    {
        PyErr_SetString(PyExc_RuntimeError, "headers have already been sent");
        return NULL;
    }

    /* Publish event for the start of the response. */

    if (wsgi_event_subscribers())
    {
        WSGIThreadInfo *thread_info;

        thread_info = wsgi_thread_info(0, 0);

        event = PyDict_New();

        if (!event)
            goto finally;

        if (self->r->log_id)
        {
            item = PyUnicode_DecodeLatin1(self->r->log_id,
                                          strlen(self->r->log_id), NULL);
            if (!item)
                goto finally;
            if (PyDict_SetItemString(event, "request_id", item) < 0)
                goto finally;
            Py_CLEAR(item);
        }

        if (PyDict_SetItemString(event, "response_status", status_line) < 0 ||
            PyDict_SetItemString(event, "response_headers", headers) < 0 ||
            PyDict_SetItemString(event, "exception_info", exc_info) < 0 ||
            PyDict_SetItemString(event, "request_data",
                                 thread_info->request_data) < 0)
            goto finally;

        wsgi_publish_event("response_started", event);

        Py_CLEAR(event);
    }

    status_line_as_bytes = wsgi_convert_status_line_to_bytes(status_line);

    if (!status_line_as_bytes)
        goto finally;

    headers_as_bytes = wsgi_convert_headers_to_bytes(headers);

    if (!headers_as_bytes)
        goto finally;

    self->status_line = apr_pstrdup(self->r->pool, PyBytes_AsString(
                                                       status_line_as_bytes));
    self->status = (int)strtol(self->status_line, NULL, 10);

    Py_XDECREF(self->headers);
    self->headers = headers_as_bytes;
    Py_INCREF(headers_as_bytes);

    result = PyObject_GetAttrString((PyObject *)self, "write");

finally:
    Py_XDECREF(event);
    Py_XDECREF(item);
    Py_XDECREF(status_line_as_bytes);
    Py_XDECREF(headers_as_bytes);

    return result;
}

static int Adapter_output(AdapterObject *self, const char *data,
                          apr_off_t length, PyObject *string_object,
                          int exception_when_aborted)
{
    Py_ssize_t i;
    Py_ssize_t headers_count;
    apr_status_t rv;
    request_rec *r;

    apr_time_t output_start = 0;
    apr_time_t output_finish = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    if (!self->status_line)
    {
        PyErr_SetString(PyExc_RuntimeError, "response has not been started");
        return 0;
    }

    r = self->r;

    /* Remember we started sending this block of output. */

    output_start = apr_time_now();

    /* Count how many separate blocks have been output. */

    if (string_object)
        self->output_writes++;

    /* Have response headers yet been sent. */

    if (self->headers)
    {
        /*
         * Now setup the response headers in request object. We
         * have already converted any native strings in the
         * headers to byte strings and validated the format of
         * the header names and values so can skip all the error
         * checking.
         */

        r->status = self->status;
        r->status_line = self->status_line;

        headers_count = PyList_Size(self->headers);

        for (i = 0; i < headers_count; i++)
        {
            PyObject *tuple = NULL;

            PyObject *object1 = NULL;
            PyObject *object2 = NULL;

            char *name = NULL;
            char *value = NULL;

            tuple = PyList_GetItem(self->headers, i);

            object1 = PyTuple_GetItem(tuple, 0);
            object2 = PyTuple_GetItem(tuple, 1);

            name = PyBytes_AsString(object1);
            value = PyBytes_AsString(object2);

            if (!strcasecmp(name, "Content-Type"))
            {
                /*
                 * In a daemon child process we cannot call the
                 * function ap_set_content_type() as want to
                 * avoid adding any output filters based on the
                 * type of file being served as this will be
                 * done in the main Apache child process which
                 * proxied the request to the daemon process.
                 */

                if (*self->config->process_group)
                    r->content_type = apr_pstrdup(r->pool, value);
                else
                    ap_set_content_type(r, apr_pstrdup(r->pool, value));
            }
            else if (!strcasecmp(name, "Content-Length"))
            {
                char *endstr;
                apr_off_t length;

                if (wsgi_strtoff(&length, value, &endstr, 10) || *endstr || length < 0)
                {

                    PyErr_SetString(PyExc_ValueError,
                                    "invalid content length");

                    output_finish = apr_time_now();

                    if (output_finish > output_start)
                        self->output_time += (output_finish - output_start);

                    return 0;
                }

                ap_set_content_length(r, length);

                self->content_length_set = 1;
                self->content_length = length;
            }
            else if (!strcasecmp(name, "WWW-Authenticate"))
            {
                apr_table_add(r->err_headers_out, name, value);
            }
            else
            {
                apr_table_add(r->headers_out, name, value);
            }
        }

        /*
         * Reset flag indicating whether '100 Continue' response
         * expected. If we don't do this then if an attempt to read
         * input for the first time is after headers have been
         * sent, then Apache is wrongly generate the '100 Continue'
         * response into the response content. Not sure if this is
         * a bug in Apache, or that it truly believes that input
         * will never be read after the response headers have been
         * sent.
         */

        r->expecting_100 = 0;

        /* No longer need headers now that they have been sent. */

        Py_DECREF(self->headers);
        self->headers = NULL;
    }

    /*
     * If content length was specified, ensure that we don't
     * actually output more data than was specified as being
     * sent as otherwise technically in violation of HTTP RFC.
     */

    if (length)
    {
        apr_off_t output_length = length;

        if (self->content_length_set)
        {
            if (self->output_length < self->content_length)
            {
                if (self->output_length + length > self->content_length)
                {
                    length = self->content_length - self->output_length;
                }
            }
            else
                length = 0;
        }

        self->output_length += output_length;
    }

    /* Now output any data. */

    if (length)
    {
        apr_bucket *b;

        /*
         * When using Apache 2.X can use lower level
         * bucket brigade APIs. This is preferred as
         * ap_rwrite()/ap_rflush() will grow memory in
         * the request pool on each call, which will
         * result in an increase in memory use over time
         * when streaming of data is being performed.
         * The memory is still reclaimed, but only at
         * the end of the request. Using bucket brigade
         * API avoids this, and also avoids any copying
         * of response data due to buffering performed
         * by ap_rwrite().
         */

        if (r->connection->aborted)
        {
            if (!exception_when_aborted)
            {
                wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                       "Client closed connection.");
            }
            else
                PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                               "connection closed.");

            output_finish = apr_time_now();

            if (output_finish > output_start)
                self->output_time += (output_finish - output_start);

            return 0;
        }

        if (!self->bb)
        {
            self->bb = apr_brigade_create(r->pool,
                                          r->connection->bucket_alloc);
        }

#if 0
        if (string_object) {
            b = wsgi_apr_bucket_python_create(data, length,
                    self->config->application_group, string_object,
                    r->connection->bucket_alloc);
        }
        else {
#endif
        b = apr_bucket_transient_create(data, (apr_size_t)length,
                                        r->connection->bucket_alloc);
#if 0
        }
#endif

        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        WSGI_BEGIN_ALLOW_THREADS
            rv = ap_pass_brigade(r->output_filters, self->bb);
        WSGI_END_ALLOW_THREADS

            if (rv != APR_SUCCESS)
        {
            char status_buffer[512];
            const char *error_message;

            if (!exception_when_aborted)
            {
                error_message = apr_psprintf(r->pool, "Unable to write "
                                                      "response data: %s",
                                             apr_strerror(rv, status_buffer,
                                                          sizeof(status_buffer) - 1));

                wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                       "%s.", error_message);
            }
            else
            {
                error_message = apr_psprintf(r->pool, "Apache/mod_wsgi "
                                                      "failed to write response data: %s",
                                             apr_strerror(rv, status_buffer,
                                                          sizeof(status_buffer) - 1));

                PyErr_SetString(PyExc_IOError, error_message);
            }

            output_finish = apr_time_now();

            if (output_finish > output_start)
                self->output_time += (output_finish - output_start);

            return 0;
        }

        WSGI_BEGIN_ALLOW_THREADS
            apr_brigade_cleanup(self->bb);
        WSGI_END_ALLOW_THREADS
    }

    /* Add how much time we spent send this block of output. */

    output_finish = apr_time_now();

    if (output_finish > output_start)
        self->output_time += (output_finish - output_start);

    /*
     * Check whether aborted connection was found when data
     * being written, otherwise will not be flagged until next
     * time that data is being written. Early detection is
     * better as it may have been the last data block being
     * written and application may think that data has all
     * been written. In a streaming application, we also want
     * to avoid any additional data processing to generate any
     * successive data.
     */

    if (r->connection->aborted)
    {
        if (!exception_when_aborted)
        {
            wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                   "Client closed connection.");
        }
        else
            PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                           "connection closed.");

        return 0;
    }

    return 1;
}

/* Split buckets at 1GB when sending large files. */

#define MAX_BUCKET_SIZE (0x40000000)

static int Adapter_output_file(AdapterObject *self, apr_file_t *tmpfile,
                               apr_off_t offset, apr_off_t len)
{
    request_rec *r;
    apr_bucket *b;
    apr_status_t rv;
    apr_bucket_brigade *bb;

    apr_file_t *dupfile = NULL;

    r = self->r;

    if (r->connection->aborted)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                       "connection closed.");
        return 0;
    }

    if (len == 0)
        return 1;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    rv = apr_file_dup(&dupfile, tmpfile, r->pool);

    if (rv != APR_SUCCESS)
    {
        char status_buffer[512];
        const char *error_message;

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi failed "
                                              "to duplicate file handle: %s.",
                                     apr_strerror(rv, status_buffer,
                                                  sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);

        WSGI_BEGIN_ALLOW_THREADS
            apr_brigade_destroy(bb);
        WSGI_END_ALLOW_THREADS

        return 0;
    }

    if (sizeof(apr_off_t) == sizeof(apr_size_t) || len < MAX_BUCKET_SIZE)
    {
        /* Can use a single bucket to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
    }
    else
    {
        /* Need to create multiple buckets to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);

        while (len > MAX_BUCKET_SIZE)
        {
            apr_bucket *cb;
            apr_bucket_copy(b, &cb);
            APR_BRIGADE_INSERT_TAIL(bb, cb);
            b->start += MAX_BUCKET_SIZE;
            len -= MAX_BUCKET_SIZE;
        }

        /* Resize just the last bucket */

        b->length = (apr_size_t)len;
    }

    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_flush_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    WSGI_BEGIN_ALLOW_THREADS
        rv = ap_pass_brigade(r->output_filters, bb);
    WSGI_END_ALLOW_THREADS

        if (rv != APR_SUCCESS)
    {
        char status_buffer[512];
        const char *error_message;

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi failed "
                                              "to write response data: %s.",
                                     apr_strerror(rv,
                                                  status_buffer, sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);
        return 0;
    }

    WSGI_BEGIN_ALLOW_THREADS
        apr_brigade_destroy(bb);
    WSGI_END_ALLOW_THREADS

        if (r->connection->aborted)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client connection "
                                       "closed.");
        return 0;
    }

    return 1;
}

static PyObject *Adapter_environ(AdapterObject *self)
{
    request_rec *r = NULL;

    PyObject *vars = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    const char *scheme = NULL;

    /* Create the WSGI environment dictionary. */

    vars = PyDict_New();

    if (!vars)
        return NULL;

    /* Merge the CGI environment into the WSGI environment. */

    r = self->r;

    head = apr_table_elts(r->subprocess_env);
    elts = (apr_table_entry_t *)head->elts;

    for (i = 0; i < head->nelts; ++i)
    {
        if (elts[i].key)
        {
            if (elts[i].val)
            {
                if (!strcmp(elts[i].val, "DOCUMENT_ROOT"))
                {
                    object = PyUnicode_DecodeFSDefault(elts[i].val);
                }
                else if (!strcmp(elts[i].val, "SCRIPT_FILENAME"))
                {
                    object = PyUnicode_DecodeFSDefault(elts[i].val);
                }
                else
                {
                    object = PyUnicode_DecodeLatin1(elts[i].val,
                                                    strlen(elts[i].val), NULL);
                }

                if (!object)
                    goto error;

                if (PyDict_SetItemString(vars, elts[i].key, object) < 0)
                    goto error;
                Py_CLEAR(object);
            }
            else
            {
                if (PyDict_SetItemString(vars, elts[i].key, Py_None) < 0)
                    goto error;
            }
        }
    }

    if (PyDict_DelItemString(vars, "PATH") < 0)
    {
        if (PyErr_ExceptionMatches(PyExc_KeyError))
            PyErr_Clear();
        else
            goto error;
    }

    /* Now setup all the WSGI specific environment values. */

    object = Py_BuildValue("(ii)", 1, 0);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.version", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyBool_FromLong(wsgi_multithread);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.multithread", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyBool_FromLong(wsgi_multiprocess);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.multiprocess", object) < 0)
        goto error;
    Py_CLEAR(object);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_daemon_process->group->threads == 1 &&
            wsgi_daemon_process->group->maximum_requests == 1)
        {
            if (PyDict_SetItemString(vars, "wsgi.run_once", Py_True) < 0)
                goto error;
        }
        else
        {
            if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
                goto error;
        }
    }
    else
    {
        if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
            goto error;
    }
#else
    if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
        goto error;
#endif

    scheme = apr_table_get(r->subprocess_env, "HTTPS");

    if (scheme && (!strcasecmp(scheme, "On") || !strcmp(scheme, "1")))
    {
        object = PyUnicode_FromString("https");
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "wsgi.url_scheme", object) < 0)
            goto error;
        Py_CLEAR(object);
    }
    else
    {
        object = PyUnicode_FromString("http");
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "wsgi.url_scheme", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    /*
     * We remove the HTTPS variable because WSGI compliant
     * applications shouldn't rely on it. Instead they should
     * use wsgi.url_scheme. We do this even if SetEnv was
     * used to set HTTPS from Apache configuration. That is
     * we convert it into the correct variable and remove the
     * original.
     */

    if (scheme)
    {
        if (PyDict_DelItemString(vars, "HTTPS") < 0)
        {
            if (PyErr_ExceptionMatches(PyExc_KeyError))
                PyErr_Clear();
            else
                goto error;
        }
    }

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    if (PyDict_SetItemString(vars, "wsgi.errors",
                             (PyObject *)self->log) < 0)
        goto error;

    /* Setup input object for request content. */

    if (PyDict_SetItemString(vars, "wsgi.input",
                             (PyObject *)self->input) < 0)
        goto error;

    if (PyDict_SetItemString(vars, "wsgi.input_terminated", Py_True) < 0)
        goto error;

    /* Setup file wrapper object for efficient file responses. */

    if (PyDict_SetItemString(vars, "wsgi.file_wrapper",
                             (PyObject *)&Stream_Type) < 0)
        goto error;

    /* Add Apache and mod_wsgi version information. */

    object = Py_BuildValue("(iii)", AP_SERVER_MAJORVERSION_NUMBER,
                           AP_SERVER_MINORVERSION_NUMBER,
                           AP_SERVER_PATCHLEVEL_NUMBER);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "apache.version", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = Py_BuildValue("(iii)", MOD_WSGI_MAJORVERSION_NUMBER,
                           MOD_WSGI_MINORVERSION_NUMBER,
                           MOD_WSGI_MICROVERSION_NUMBER);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.version", object) < 0)
        goto error;
    Py_CLEAR(object);

    /*
     * If Apache extensions are enabled and running in embedded
     * mode add a CObject reference to the Apache request_rec
     * structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request)
    {
        object = PyCapsule_New(self->r, 0, 0);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "apache.request_rec", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    return vars;

error:
    Py_XDECREF(object);
    Py_DECREF(vars);
    return NULL;
}

static int Adapter_process_file_wrapper(AdapterObject *self)
{
    int done = 0;

#ifndef WIN32
    PyObject *filelike = NULL;
    PyObject *method = NULL;
    PyObject *object = NULL;

    apr_status_t rv = 0;

    apr_os_file_t fd = -1;
    apr_file_t *tmpfile = NULL;
    apr_finfo_t finfo;

    apr_off_t fd_offset = 0;
    apr_off_t fo_offset = 0;

    apr_off_t length = 0;

    /* Perform file wrapper optimisations where possible. */

    {
        int is_instance;

        is_instance = PyObject_IsInstance(self->sequence,
                                          (PyObject *)&Stream_Type);

        if (is_instance == -1)
        {
            PyErr_Clear();
            return 0;
        }

        if (!is_instance)
            return 0;
    }

    /*
     * Only attempt to perform optimisations if the
     * write() function returned by start_response()
     * function has not been called with non zero length
     * data. In other words if no prior response content
     * generated. Technically it could be done, but want
     * to have a consistent rule about how specifying a
     * content length affects how much of a file is
     * sent. Don't want to have to take into
     * consideration whether write() function has been
     * called or not as just complicates things.
     */

    if (self->output_length != 0)
        return 0;

    /*
     * Work out if file wrapper is associated with a
     * file like object, where that file object is
     * associated with a regular file. If it does then
     * we can optimise how the contents of the file are
     * sent out. If no such associated file descriptor
     * then it needs to be processed like any other
     * iterable value.
     */

    filelike = PyObject_GetAttrString((PyObject *)self->sequence, "filelike");

    if (!filelike)
    {
        PyErr_Clear();
        return 0;
    }

    fd = PyObject_AsFileDescriptor(filelike);
    if (fd == -1)
    {
        PyErr_Clear();
        Py_DECREF(filelike);
        return 0;
    }

    /*
     * On some platforms, such as Linux, sendfile() system call
     * will not work on UNIX sockets. Thus when using daemon mode
     * cannot enable that feature.
     */

    if (self->config->enable_sendfile)
        apr_os_file_put(&tmpfile, &fd, APR_SENDFILE_ENABLED, self->r->pool);
    else
        apr_os_file_put(&tmpfile, &fd, 0, self->r->pool);

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_TYPE, tmpfile);
    if (rv != APR_SUCCESS || finfo.filetype != APR_REG)
    {
        Py_DECREF(filelike);
        return 0;
    }

    /*
     * Because Python file like objects potentially have
     * their own buffering layering, or use an operating
     * system FILE object which also has a buffering
     * layer on top of a normal file descriptor, need to
     * determine from the file like object its position
     * within the file and use that as starting position.
     * Note that it is assumed that user had flushed any
     * modifications to the file as necessary. Also, we
     * need to make sure we remember the original file
     * descriptor position as will need to restore that
     * position so it matches the upper buffering layers
     * when done. This is done to avoid any potential
     * problems if file like object does anything strange
     * in its close() method which relies on file position
     * being what it thought it should be.
     */

    rv = apr_file_seek(tmpfile, APR_CUR, &fd_offset);
    if (rv != APR_SUCCESS)
    {
        Py_DECREF(filelike);
        return 0;
    }

    method = PyObject_GetAttrString(filelike, "tell");
    Py_DECREF(filelike);
    if (!method)
    {
        PyErr_Clear();
        return 0;
    }

    object = PyObject_CallObject(method, NULL);
    Py_DECREF(method);

    if (!object)
    {
        PyErr_Clear();
        return 0;
    }

    if (PyLong_Check(object))
    {
        fo_offset = PyLong_AsLongLong(object);
    }
    else
    {
        Py_DECREF(object);
        return 0;
    }

    if (PyErr_Occurred())
    {
        Py_DECREF(object);
        PyErr_Clear();
        return 0;
    }

    Py_DECREF(object);

    /*
     * For a file wrapper object need to always ensure
     * that response headers are parsed. This is done so
     * that if the content length header has been
     * defined we can get its value and use it to limit
     * how much of a file is being sent. The WSGI 1.0
     * specification says that we are meant to send all
     * available bytes from the file, however this is
     * questionable as sending more than content length
     * would violate HTTP RFC. Note that this doesn't
     * actually flush the headers out when using Apache
     * 2.X. This is good, as we want to still be able to
     * set the content length header if none set and file
     * is seekable. If processing response headers fails,
     * then need to return as if done, with error being
     * logged later.
     */

    if (!Adapter_output(self, "", 0, NULL, 0))
        return 1;

    /*
     * If content length wasn't defined then determine
     * the amount of data which is available to send and
     * set the content length response header. Either
     * way, if can work out length then send data
     * otherwise fall through and treat it as normal
     * iterable.
     */

    if (!self->content_length_set)
    {
        length = finfo.size - fo_offset;
        self->output_length += length;

        ap_set_content_length(self->r, length);

        self->content_length_set = 1;
        self->content_length = length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }
    else
    {
        length = finfo.size - fo_offset;
        self->output_length += length;

        /* Use user specified content length instead. */

        length = self->content_length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }

    /*
     * Restore position of underlying file descriptor.
     * If this fails, then not much we can do about it.
     */

    apr_file_seek(tmpfile, APR_SET, &fd_offset);

#endif

    return done;
}

int Adapter_run(AdapterObject *self, PyObject *object)
{
    PyObject *vars = NULL;
    PyObject *start = NULL;
    PyObject *args = NULL;
    PyObject *iterator = NULL;
    PyObject *close = NULL;

    PyObject *evwrapper = NULL;

    PyObject *value = NULL;
    PyObject *event = NULL;

    const char *msg = NULL;
    apr_off_t length = 0;

    WSGIThreadInfo *thread_handle = NULL;

    apr_time_t finish_time;

    WSGIThreadCPUUsage start_usage;
    WSGIThreadCPUUsage end_usage;

    int aborted = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    self->start_time = apr_time_now();

    /* Make application_start visible to the slow-record active-snapshot
     * path; without this an in-flight slow request would fall back to
     * slot->start_us (the slot-claim instant, before module load) and
     * conflate framework-load time with application time. */
    wsgi_record_application_start(self->start_time);

    apr_table_setn(self->r->subprocess_env, "mod_wsgi.script_start",
                   apr_psprintf(self->r->pool, "%" APR_TIME_T_FMT,
                                self->start_time));

    vars = Adapter_environ(self);

    if (!vars)
        goto error;

    value = PyLong_FromLongLong(wsgi_total_requests);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.total_requests", value) < 0)
        goto error;
    Py_CLEAR(value);

    thread_handle = wsgi_thread_info(1, 1);

    value = PyLong_FromLong(thread_handle->thread_id);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.thread_id", value) < 0)
        goto error;
    Py_CLEAR(value);

    value = PyLong_FromLongLong(thread_handle->request_count);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.thread_requests", value) < 0)
        goto error;
    Py_CLEAR(value);

    /* Publish event for the start of the request. */

    start_usage.user_time = 0.0;
    start_usage.system_time = 0.0;

    if (wsgi_event_subscribers())
    {
        wsgi_thread_cpu_usage(&start_usage);

        event = PyDict_New();

        if (!event)
            goto error;

        if (self->r->log_id)
        {
            value = PyUnicode_DecodeLatin1(self->r->log_id,
                                           strlen(self->r->log_id), NULL);
            if (!value)
                goto error;
            if (PyDict_SetItemString(event, "request_id", value) < 0)
                goto error;
            Py_CLEAR(value);
        }

        value = PyLong_FromLong(thread_handle->thread_id);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "thread_id", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyLong_FromLong(self->config->daemon_connects);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_connects", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyLong_FromLong(self->config->daemon_restarts);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_restarts", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->request_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "request_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->queue_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "queue_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->daemon_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        if (PyDict_SetItemString(event, "application_object", object) < 0)
            goto error;

        if (PyDict_SetItemString(event, "request_environ", vars) < 0)
            goto error;

        value = PyFloat_FromDouble(apr_time_sec((double)self->start_time));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "application_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        if (PyDict_SetItemString(event, "request_data",
                                 thread_handle->request_data) < 0)
            goto error;

        wsgi_publish_event("request_started", event);

        evwrapper = PyDict_GetItemString(event, "application_object");

        if (evwrapper)
        {
            if (evwrapper != object)
            {
                Py_INCREF(evwrapper);
                object = evwrapper;
            }
            else
                evwrapper = NULL;
        }

        Py_CLEAR(event);
    }

    /* Pass the request through to the WSGI application. */

    thread_handle->request_count++;

    start = PyObject_GetAttrString((PyObject *)self, "start_response");

    args = Py_BuildValue("(OO)", vars, start);

    if (args)
        self->sequence = PyObject_CallObject(object, args);

    if (self->sequence != NULL)
    {
        if (!Adapter_process_file_wrapper(self))
        {
            iterator = PyObject_GetIter(self->sequence);

            if (iterator != NULL)
            {
                PyObject *item = NULL;

                while ((item = PyIter_Next(iterator)))
                {
                    if (!PyBytes_Check(item))
                    {
                        PyErr_Format(PyExc_TypeError, "sequence of byte "
                                                      "string values expected, value of "
                                                      "type %.200s found",
                                     item->ob_type->tp_name);
                        Py_DECREF(item);
                        break;
                    }

                    msg = PyBytes_AsString(item);
                    length = PyBytes_Size(item);

                    if (!msg)
                    {
                        Py_DECREF(item);
                        break;
                    }

                    if (length && !Adapter_output(self, msg, length,
                                                  item, 0))
                    {
                        if (!PyErr_Occurred())
                            aborted = 1;
                        Py_DECREF(item);
                        break;
                    }

                    Py_DECREF(item);
                }
            }

            if (!PyErr_Occurred())
            {
                if (!aborted)
                {
                    /*
                     * In the case where the response was empty we
                     * need to ensure we explicitly flush out the
                     * headers. This is done by calling the output
                     * routine but with an empty string as content.
                     * This could be gated on whether any content
                     * had already been sent, but easier to just call
                     * it all the time.
                     */

                    if (Adapter_output(self, "", 0, NULL, 0))
                        self->result = OK;
                }
                else
                {
                    /*
                     * If the client connection was already marked
                     * as aborted, then it indicates the client has
                     * closed the connection. In this case mark the
                     * final result as okay rather than an error so
                     * that the access log still records the original
                     * HTTP response code for the request rather than
                     * overriding it. If don't do this then access
                     * log will show 500 when the WSGI application
                     * itself had run fine.
                     */

                    self->result = OK;
                }
            }

            Py_XDECREF(iterator);
        }

        /*
         * Log warning if more response content generated than was
         * indicated, or less, if there was no errors generated by
         * the application and connection wasn't aborted.
         */

        if (self->content_length_set && ((!PyErr_Occurred() && !aborted &&
                                          self->output_length != self->content_length) ||
                                         (self->output_length > self->content_length)))
        {
            wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                   "Content length mismatch, expected %s, "
                                   "response generated %s: %s",
                                   apr_off_t_toa(self->r->pool,
                                                 self->content_length),
                                   apr_off_t_toa(self->r->pool,
                                                 self->output_length),
                                   self->r->filename);
        }

        if (PyErr_Occurred())
        {
            int is_request_timeout = 0;

            if (wsgi_request_timeout_exc &&
                PyErr_ExceptionMatches(wsgi_request_timeout_exc))
                is_request_timeout = 1;

            if (is_request_timeout && !(self->status_line && !self->headers))
            {
                /*
                 * RequestTimeout was injected and reached the adapter
                 * before the response headers were flushed. Produce a
                 * 504 Gateway Timeout response. The worker thread
                 * returns to the pool; the process is not shut down.
                 */

                self->r->status = HTTP_GATEWAY_TIME_OUT;
                self->r->status_line = "504 Gateway Timeout";
                self->status = HTTP_GATEWAY_TIME_OUT;
                self->result = OK;

                PyErr_Clear();

                wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                       "Request interrupted by "
                                       "RequestTimeout; thread "
                                       "recovered.");
            }
            else
            {
                /*
                 * Response content has already been sent, so cannot
                 * return an internal server error as Apache will
                 * append its own error page. Thus need to return OK
                 * and just truncate the response.
                 */

                if (self->status_line && !self->headers)
                    self->result = OK;

                if (is_request_timeout)
                {
                    /*
                     * RequestTimeout but the headers were already
                     * flushed; the wire status is committed and we
                     * can only truncate. Clear the exception so it
                     * isn't logged as an unhandled error.
                     */

                    PyErr_Clear();

                    wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                           "Request interrupted by "
                                           "RequestTimeout after headers "
                                           "sent; response truncated.");
                }
                else
                    wsgi_log_python_error(self->r, self->r->filename,
                                          NULL, 1);

                /*
                 * If response content is being chunked and an error
                 * occurred, we need to prevent the sending of the EOS
                 * bucket so a client is able to detect that the the
                 * response was incomplete.
                 */

                if (self->r->chunked)
                    self->r->eos_sent = 1;
            }
        }

        if (PyObject_HasAttrString(self->sequence, "close"))
        {
            PyObject *args = NULL;
            PyObject *data = NULL;

            close = PyObject_GetAttrString(self->sequence, "close");

            if (close)
            {
                args = Py_BuildValue("()");

                if (args)
                {
                    data = PyObject_CallObject(close, args);
                    Py_XDECREF(data);
                    Py_DECREF(args);
                }

                Py_DECREF(close);
            }
        }

        if (PyErr_Occurred())
        {
            if (wsgi_request_timeout_exc &&
                PyErr_ExceptionMatches(wsgi_request_timeout_exc))
            {
                PyErr_Clear();
            }
            else
                wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
        }
    }
    else
    {
        /*
         * The WSGI application call itself raised (no sequence
         * returned). If RequestTimeout was injected before
         * start_response was called, produce a 504 directly and
         * return the worker to the pool. Otherwise log the error
         * normally and let the default 500 result apply.
         */

        if (wsgi_request_timeout_exc &&
            PyErr_ExceptionMatches(wsgi_request_timeout_exc))
        {
            self->r->status = HTTP_GATEWAY_TIME_OUT;
            self->r->status_line = "504 Gateway Timeout";
            self->status = HTTP_GATEWAY_TIME_OUT;
            self->result = OK;

            PyErr_Clear();

            wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                   "Request interrupted by "
                                   "RequestTimeout; thread "
                                   "recovered.");
        }
        else
            wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
    }

    /* Publish event for the end of the request. */

    finish_time = apr_time_now();

    if (wsgi_event_subscribers())
    {
        double application_time = 0.0;
        double output_time = 0.0;

        event = PyDict_New();

        if (event)
        {
            if (self->r->log_id)
            {
                value = PyUnicode_DecodeLatin1(self->r->log_id,
                                               strlen(self->r->log_id), NULL);
                if (value)
                {
                    if (PyDict_SetItemString(event, "request_id", value) < 0)
                        goto event_error;
                    Py_CLEAR(value);
                }
                else
                    goto event_error;
            }

            value = PyLong_FromLongLong(self->input->reads);
            if (value)
            {
                if (PyDict_SetItemString(event, "input_reads", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->input->bytes);
            if (value)
            {
                if (PyDict_SetItemString(event, "input_length", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec((double)self->input->time));
            if (value)
            {
                if (PyDict_SetItemString(event, "input_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->output_length);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_length", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->output_writes);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_writes", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            output_time = apr_time_sec((double)self->output_time);

            if (output_time < 0.0)
                output_time = 0.0;

            application_time = apr_time_sec((double)finish_time - self->start_time);

            if (application_time < 0.0)
                application_time = 0.0;

            if (start_usage.user_time != 0.0)
            {
                if (wsgi_thread_cpu_usage(&end_usage))
                {
                    double user_seconds;
                    double system_seconds;
                    double total_seconds;

                    user_seconds = end_usage.user_time;
                    user_seconds -= start_usage.user_time;

                    if (user_seconds < 0.0)
                        user_seconds = 0.0;

                    system_seconds = end_usage.system_time;
                    system_seconds -= start_usage.system_time;

                    if (system_seconds < 0.0)
                        system_seconds = 0.0;

                    total_seconds = user_seconds + system_seconds;

                    if (total_seconds && total_seconds > application_time)
                    {
                        user_seconds = (user_seconds / total_seconds) * application_time;
                        system_seconds = application_time - user_seconds;
                    }

                    value = PyFloat_FromDouble(user_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_user_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;

                    value = PyFloat_FromDouble(system_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_system_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;

                    value = PyFloat_FromDouble(user_seconds + system_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;
                }
            }

            value = PyFloat_FromDouble(output_time);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec((double)finish_time));
            if (value)
            {
                if (PyDict_SetItemString(event, "application_finish", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(application_time);
            if (value)
            {
                if (PyDict_SetItemString(event, "application_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            if (PyDict_SetItemString(event, "request_data",
                                     thread_handle->request_data) < 0)
                goto event_error;

            /*
             * If any allocation while building the event failed,
             * discard the partial event rather than publishing
             * misleading data to subscribers. wsgi_log_python_error
             * also clears the exception so the subscriber callbacks
             * aren't invoked with an error pending.
             */

event_error:
            if (PyErr_Occurred())
                wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
            else
                wsgi_publish_event("request_finished", event);

            Py_XDECREF(value);
            Py_CLEAR(event);
        }
        else
            wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
    }

    /*
     * Record server and application time for metrics. Values
     * are the time request first accepted by child workers,
     * the time that the WSGI application started processing
     * the request, and when the WSGI application finished the
     * request.
     */

    wsgi_record_request_times(self->config->request_start,
                              self->config->queue_start, self->config->daemon_start,
                              self->start_time, finish_time,
                              self->input ? self->input->bytes : 0,
                              self->input ? self->input->reads : 0,
                              self->output_length, self->output_writes,
                              self->status);

    /*
     * If result indicates an internal server error, then
     * replace the status line in the request object else
     * that provided by the application will be what is used
     * in any error page automatically generated by Apache.
     */

error:
    if (PyErr_Occurred())
        wsgi_log_python_error(self->r, self->r->filename, NULL, 1);

    if (self->result == HTTP_INTERNAL_SERVER_ERROR)
        self->r->status_line = "500 Internal Server Error";

    Py_XDECREF(args);
    Py_XDECREF(start);
    Py_XDECREF(vars);

    Py_XDECREF(event);
    Py_XDECREF(value);

    Py_XDECREF(evwrapper);

    Py_CLEAR(self->sequence);

    return self->result;
}

static PyObject *Adapter_write(AdapterObject *self, PyObject *args)
{
    PyObject *item = NULL;
    const char *data = NULL;
    Py_ssize_t length = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:write", &item))
        return NULL;

    if (!PyBytes_Check(item))
    {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                                      "of type %.200s found",
                     item->ob_type->tp_name);
        return NULL;
    }

    data = PyBytes_AsString(item);
    length = PyBytes_Size(item);

    if (!Adapter_output(self, data, length, item, 1))
    {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *Adapter_ssl_is_https(AdapterObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":ssl_is_https"))
        return NULL;

    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (ssl_is_https == 0)
        return Py_BuildValue("i", 0);

    return Py_BuildValue("i", ssl_is_https(self->r->connection));
}

static PyObject *Adapter_ssl_var_lookup(AdapterObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = 0;

    PyObject *item = NULL;
    PyObject *latin_item = NULL;

    char *name = 0;
    char *value = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:ssl_var_lookup", &item))
        return NULL;

    if (PyUnicode_Check(item))
    {
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item)
        {
            PyErr_Format(PyExc_TypeError, "byte string value expected, "
                                          "value containing non 'latin-1' characters found");

            return NULL;
        }

        item = latin_item;
    }

    if (!PyBytes_Check(item))
    {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                                      "of type %.200s found",
                     item->ob_type->tp_name);

        Py_XDECREF(latin_item);

        return NULL;
    }

    name = PyBytes_AsString(item);

    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (ssl_var_lookup == 0)
    {
        Py_XDECREF(latin_item);

        Py_RETURN_NONE;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    Py_XDECREF(latin_item);

    if (!value)
    {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
}

static PyMethodDef Adapter_methods[] = {
    {"start_response", (PyCFunction)Adapter_start_response, METH_VARARGS, 0},
    {"write", (PyCFunction)Adapter_write, METH_VARARGS, 0},
    {"ssl_is_https", (PyCFunction)Adapter_ssl_is_https, METH_VARARGS, 0},
    {"ssl_var_lookup", (PyCFunction)Adapter_ssl_var_lookup, METH_VARARGS, 0},
    {NULL, NULL}};

PyTypeObject Adapter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.Adapter", /*tp_name*/
    sizeof(AdapterObject),                             /*tp_basicsize*/
    0,                                                 /*tp_itemsize*/
    /* methods */
    (destructor)Adapter_dealloc, /*tp_dealloc*/
    0,                           /*tp_print*/
    0,                           /*tp_getattr*/
    0,                           /*tp_setattr*/
    0,                           /*tp_compare*/
    0,                           /*tp_repr*/
    0,                           /*tp_as_number*/
    0,                           /*tp_as_sequence*/
    0,                           /*tp_as_mapping*/
    0,                           /*tp_hash*/
    0,                           /*tp_call*/
    0,                           /*tp_str*/
    0,                           /*tp_getattro*/
    0,                           /*tp_setattro*/
    0,                           /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,          /*tp_flags*/
    0,                           /*tp_doc*/
    0,                           /*tp_traverse*/
    0,                           /*tp_clear*/
    0,                           /*tp_richcompare*/
    0,                           /*tp_weaklistoffset*/
    0,                           /*tp_iter*/
    0,                           /*tp_iternext*/
    Adapter_methods,             /*tp_methods*/
    0,                           /*tp_members*/
    0,                           /*tp_getset*/
    0,                           /*tp_base*/
    0,                           /*tp_dict*/
    0,                           /*tp_descr_get*/
    0,                           /*tp_descr_set*/
    0,                           /*tp_dictoffset*/
    0,                           /*tp_init*/
    0,                           /*tp_alloc*/
    0,                           /*tp_new*/
    0,                           /*tp_free*/
    0,                           /*tp_is_gc*/
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
