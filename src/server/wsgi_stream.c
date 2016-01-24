/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2016 GRAHAM DUMPLETON
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

/* ------------------------------------------------------------------------- */

PyTypeObject Stream_Type;

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
    apr_size_t blksize = HUGE_STRING_LEN;

    static char *kwlist[] = { "filelike", "blksize", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|l:FileWrapper", kwlist,
                                     &filelike, &blksize)) {
        return -1;
    }

    if (filelike) {
        PyObject *tmp = NULL;

        tmp = self->filelike;
        Py_INCREF(filelike);
        self->filelike = filelike;
        Py_XDECREF(tmp);
    }

    self->blksize = blksize;

    return 0;
}

static void Stream_dealloc(StreamObject *self)
{
    Py_XDECREF(self->filelike);

    Py_TYPE(self)->tp_free(self);
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

    attribute = PyObject_GetAttrString((PyObject *)self, "filelike");

    if (!attribute) {
        PyErr_SetString(PyExc_KeyError,
                        "file wrapper no filelike attribute");
        return 0;
    }

    method = PyObject_GetAttrString(attribute, "read");

    if (!method) {
        PyErr_SetString(PyExc_KeyError,
                        "file like object has no read() method");
        Py_DECREF(attribute);
        return 0;
    }

    Py_DECREF(attribute);

    attribute = PyObject_GetAttrString((PyObject *)self, "blksize");

    if (!attribute) {
        PyErr_SetString(PyExc_KeyError,
                        "file wrapper has no blksize attribute");
        Py_DECREF(method);
        return 0;
    }

    if (!PyLong_Check(attribute)) {
        PyErr_SetString(PyExc_KeyError,
                        "file wrapper blksize attribute not integer");
        Py_DECREF(method);
        Py_DECREF(attribute);
        return 0;
    }

    args = Py_BuildValue("(O)", attribute);
    result = PyEval_CallObject(method, args);

    Py_DECREF(args);
    Py_DECREF(method);
    Py_DECREF(attribute);

    if (!result)
        return 0;

    if (PyString_Check(result)) {
        if (PyString_Size(result) == 0) {
            PyErr_SetObject(PyExc_StopIteration, Py_None);
            Py_DECREF(result);
            return 0;
        }

        return result;
    }

    Py_DECREF(result);

    PyErr_SetString(PyExc_TypeError,
                    "file like object yielded non string type");

    return 0;
}

static PyObject *Stream_close(StreamObject *self, PyObject *args)
{
    PyObject *method = NULL;
    PyObject *result = NULL;

    if (!self->filelike || self->filelike == Py_None) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    method = PyObject_GetAttrString(self->filelike, "close");

    if (method) {
        result = PyEval_CallObject(method, (PyObject *)NULL);
        if (!result)
            PyErr_Clear();
        Py_DECREF(method);
    }

    Py_XDECREF(result);

    Py_DECREF(self->filelike);
    self->filelike = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Stream_get_filelike(StreamObject *self, void *closure)
{
    Py_INCREF(self->filelike);
    return self->filelike;
}


static PyObject *Stream_get_blksize(StreamObject *self, void *closure)
{
    return PyLong_FromLong(self->blksize);
}

static PyMethodDef Stream_methods[] = {
    { "close",      (PyCFunction)Stream_close,      METH_NOARGS, 0 },
    { NULL, NULL }
};

static PyGetSetDef Stream_getset[] = {
    { "filelike", (getter)Stream_get_filelike, NULL, 0 },
    { "blksize",  (getter)Stream_get_blksize, NULL, 0 },
    { NULL },
};

PyTypeObject Stream_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.FileWrapper", /*tp_name*/
    sizeof(StreamObject),   /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Stream_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
#if defined(Py_TPFLAGS_HAVE_ITER)
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
#else
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
#endif
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    (getiterfunc)Stream_iter, /*tp_iter*/
    (iternextfunc)Stream_iternext, /*tp_iternext*/
    Stream_methods,         /*tp_methods*/
    0,                      /*tp_members*/
    Stream_getset,          /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    (initproc)Stream_init,  /*tp_init*/
    0,                      /*tp_alloc*/
    Stream_new,             /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
