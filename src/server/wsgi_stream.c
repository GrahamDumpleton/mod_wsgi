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

#include "wsgi_stream.h"

#include "wsgi_module.h"

/* ------------------------------------------------------------------------- */

static PyObject *Stream_new(PyTypeObject *type, PyObject *args,
                            PyObject *kwds)
{
    StreamObject *self;

    self = (StreamObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->filelike = Py_None;
    Py_INCREF(self->filelike);

    self->blksize = 0;

    return (PyObject *)self;
}

static int Stream_init(StreamObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *filelike = NULL;
    Py_ssize_t blksize = HUGE_STRING_LEN;

    static char *kwlist[] = {"filelike", "blksize", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|n:FileWrapper", kwlist,
                                     &filelike, &blksize))
    {
        return -1;
    }

    if (blksize < 0)
    {
        PyErr_SetString(PyExc_ValueError,
                        "blksize must not be negative");
        return -1;
    }

    if (filelike)
    {
        PyObject *tmp = NULL;

        tmp = self->filelike;
        Py_INCREF(filelike);
        self->filelike = filelike;
        Py_XDECREF(tmp);
    }

    self->blksize = blksize;

    return 0;
}

/*
 * Heap-type destructor. Releases the wrapped file-like reference,
 * frees the instance memory via the type's tp_free, and decrements
 * the type's refcount (every heap-type instance owns a reference
 * to its type).
 */

static void Stream_dealloc(StreamObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    Py_XDECREF(self->filelike);

    tp->tp_free(self);
    Py_DECREF(tp);
}

static PyObject *Stream_iter(StreamObject *self)
{
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *Stream_iternext(StreamObject *self)
{
    PyObject *attribute = NULL;
    PyObject *method = NULL;
    PyObject *args = NULL;
    PyObject *result = NULL;

    if (!self->filelike)
    {
        PyErr_SetString(PyExc_ValueError,
                        "I/O operation on closed file");
        return NULL;
    }

    attribute = PyObject_GetAttrString((PyObject *)self, "filelike");

    if (!attribute)
        return NULL;

    method = PyObject_GetAttrString(attribute, "read");

    if (!method)
    {
        Py_DECREF(attribute);
        return NULL;
    }

    Py_DECREF(attribute);

    attribute = PyObject_GetAttrString((PyObject *)self, "blksize");

    if (!attribute)
    {
        Py_DECREF(method);
        return NULL;
    }

    if (!PyLong_Check(attribute))
    {
        PyErr_Format(PyExc_TypeError,
                     "blksize must be an int, not %.200s",
                     Py_TYPE(attribute)->tp_name);
        Py_DECREF(method);
        Py_DECREF(attribute);
        return NULL;
    }

    args = Py_BuildValue("(O)", attribute);

    if (!args)
    {
        Py_DECREF(method);
        Py_DECREF(attribute);
        return NULL;
    }

    result = PyObject_CallObject(method, args);

    Py_DECREF(args);
    Py_DECREF(method);
    Py_DECREF(attribute);

    if (!result)
        return NULL;

    if (PyBytes_Check(result))
    {
        if (PyBytes_Size(result) == 0)
        {
            PyErr_SetObject(PyExc_StopIteration, Py_None);
            Py_DECREF(result);
            return NULL;
        }

        return result;
    }

    PyErr_Format(PyExc_TypeError,
                 "file wrapper read() must return bytes, not %.200s",
                 Py_TYPE(result)->tp_name);

    Py_DECREF(result);

    return NULL;
}

static PyObject *Stream_close(StreamObject *self, PyObject *Py_UNUSED(args))
{
    PyObject *method = NULL;
    PyObject *result = NULL;

    if (!self->filelike || self->filelike == Py_None)
        Py_RETURN_NONE;

    method = PyObject_GetAttrString(self->filelike, "close");

    if (method)
    {
        result = PyObject_CallObject(method, (PyObject *)NULL);
        if (!result)
            PyErr_Clear();
        Py_DECREF(method);
    }

    Py_XDECREF(result);

    Py_DECREF(self->filelike);
    self->filelike = NULL;

    Py_RETURN_NONE;
}

static PyObject *Stream_get_filelike(StreamObject *self,
                                     void *Py_UNUSED(closure))
{
    if (!self->filelike)
    {
        PyErr_SetString(PyExc_ValueError,
                        "I/O operation on closed file");
        return NULL;
    }

    Py_INCREF(self->filelike);
    return self->filelike;
}

static PyObject *Stream_get_blksize(StreamObject *self,
                                    void *Py_UNUSED(closure))
{
    return PyLong_FromSsize_t(self->blksize);
}

static PyMethodDef Stream_methods[] = {
    {"close", (PyCFunction)Stream_close, METH_NOARGS, 0},
    {NULL, NULL}};

static PyGetSetDef Stream_getset[] = {
    {"filelike", (getter)Stream_get_filelike, NULL, 0},
    {"blksize", (getter)Stream_get_blksize, NULL, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

/*
 * PyType_Spec for the Stream heap type. The slots with non-default
 * behaviour are tp_dealloc (releases the wrapped file-like),
 * tp_iter / tp_iternext (the chunk-reader iteration protocol),
 * tp_methods (close), tp_getset (filelike / blksize properties),
 * tp_init / tp_new (Python-level construction). Everything else
 * falls back to the framework defaults.
 *
 * tp_name is "mod_wsgi.FileWrapper" because the type is exposed
 * to applications under that name. Py_TPFLAGS_BASETYPE is set so
 * that Python code can subclass FileWrapper to extend the basic
 * file_wrapper behaviour.
 */

static PyType_Slot Stream_slots[] = {
    {Py_tp_dealloc, Stream_dealloc},
    {Py_tp_iter, Stream_iter},
    {Py_tp_iternext, Stream_iternext},
    {Py_tp_methods, Stream_methods},
    {Py_tp_getset, Stream_getset},
    {Py_tp_init, Stream_init},
    {Py_tp_new, Stream_new},
    {0, NULL},
};

static PyType_Spec Stream_spec = {
    .name = "mod_wsgi.FileWrapper",
    .basicsize = sizeof(StreamObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .slots = Stream_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_stream_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &Stream_spec, NULL);
    if (!type)
        return -1;

    state->Stream_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

PyTypeObject *wsgi_stream_type(void)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the Stream heap type out of its
     * state. The module reference is dropped before returning;
     * the type pointer remains valid for the lifetime of the
     * interpreter because WSGIModuleState owns a reference to
     * the type.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Stream_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Stream type not initialised for the current "
                        "interpreter; wsgi_stream_type() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Stream_Type;

    Py_DECREF(module);

    return type;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
