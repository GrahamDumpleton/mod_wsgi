#ifndef WSGI_STREAM_H
#define WSGI_STREAM_H

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

#include "wsgi_python.h"
#include "wsgi_apache.h"

/* ------------------------------------------------------------------------- */

/*
 * Stream: the WSGI file wrapper, exposed to Python code as
 * mod_wsgi.FileWrapper and per-request as
 * environ["wsgi.file_wrapper"]. A Stream wraps any file-like
 * object together with a chunk size and iterates it by reading
 * blksize bytes at a time, returning bytes objects until read()
 * yields an empty bytes (treated as end of iteration). When a
 * WSGI application returns a Stream as its response body the
 * adapter recognises it and may bypass the iterator protocol
 * entirely, sending the underlying OS file directly via
 * sendfile / mmap-friendly paths in Apache.
 *
 * The type is constructed only from Python (no C-level
 * newStreamObject), and is subclassable so applications can
 * extend the basic file_wrapper behaviour.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState; the
 * convenience wsgi_stream_type() helper hides that lookup for
 * call sites in the request-handling path.
 */

typedef struct
{
    PyObject_HEAD PyObject *filelike;
    Py_ssize_t blksize;
} StreamObject;

/*
 * Create the heap-allocated Stream PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success,
 * -1 on failure with Python exception set.
 */

extern int wsgi_stream_init(PyObject *module);

/*
 * Return a borrowed reference to the Stream heap type for the
 * current interpreter, or NULL with a Python exception set if
 * the embedded mod_wsgi module is not yet in sys.modules or its
 * state has not been initialised. Used by call sites that need
 * the type without owning a reference (PyDict_SetItemString of
 * 'wsgi.file_wrapper', PyObject_IsInstance of a response body).
 */

extern PyTypeObject *wsgi_stream_type(void);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
