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

#include "wsgi_convert.h"

#include "wsgi_validate.h"

/* ------------------------------------------------------------------------- */

PyObject *wsgi_convert_string_to_bytes(PyObject *value)
{
    PyObject *result = NULL;

#if PY_MAJOR_VERSION >= 3
    if (!PyUnicode_Check(value)) {
        PyErr_Format(PyExc_TypeError, "expected unicode object, value "
                     "of type %.200s found", value->ob_type->tp_name);
        return NULL;
    }

    result = PyUnicode_AsLatin1String(value);

    if (!result) {
        PyErr_SetString(PyExc_ValueError, "unicode object contains non "
                        "latin-1 characters");
        return NULL;
    }
#else
    if (!PyBytes_Check(value)) {
        PyErr_Format(PyExc_TypeError, "expected byte string object, "
                     "value of type %.200s found", value->ob_type->tp_name);
        return NULL;
    }

    Py_INCREF(value);
    result = value;
#endif

    return result;
}

/* ------------------------------------------------------------------------- */

PyObject *wsgi_convert_status_line_to_bytes(PyObject *status_line)
{
    PyObject *result = NULL;

    result = wsgi_convert_string_to_bytes(status_line);

    if (!result)
        return NULL;

    if (!wsgi_validate_status_line(result)) {
        Py_DECREF(result);
        return NULL;
    }

    return result;
}

/* ------------------------------------------------------------------------- */

PyObject *wsgi_convert_headers_to_bytes(PyObject *headers)
{
    PyObject *result = NULL;

    int i;
    long size;

    if (!PyList_Check(headers)) {
        PyErr_Format(PyExc_TypeError, "expected list object for headers, "
                     "value of type %.200s found", headers->ob_type->tp_name);
        return 0;
    }

    size = PyList_Size(headers);
    result = PyList_New(size);

    for (i = 0; i < size; i++) {
        PyObject *header = NULL;

        PyObject *header_name = NULL;
        PyObject *header_value = NULL;

        PyObject *header_name_as_bytes = NULL;
        PyObject *header_value_as_bytes = NULL;

        PyObject *result_tuple = NULL;

        header = PyList_GetItem(headers, i);

        if (!PyTuple_Check(header)) {
            PyErr_Format(PyExc_TypeError, "list of tuple values "
                         "expected for headers, value of type %.200s found",
                         header->ob_type->tp_name);
            Py_DECREF(result);
            return 0;
        }

        if (PyTuple_Size(header) != 2) {
            PyErr_Format(PyExc_ValueError, "tuple of length 2 "
                         "expected for header, length is %d",
                         (int)PyTuple_Size(header));
            Py_DECREF(result);
            return 0;
        }

        result_tuple = PyTuple_New(2);
        PyList_SET_ITEM(result, i, result_tuple);

        header_name = PyTuple_GetItem(header, 0);
        header_value = PyTuple_GetItem(header, 1);

        header_name_as_bytes = wsgi_convert_string_to_bytes(header_name);

        if (!header_name_as_bytes)
            goto failure;

        PyTuple_SET_ITEM(result_tuple, 0, header_name_as_bytes);

        if (!wsgi_validate_header_name(header_name_as_bytes))
            goto failure;

        header_value_as_bytes = wsgi_convert_string_to_bytes(header_value);

        if (!header_value_as_bytes)
            goto failure;

        PyTuple_SET_ITEM(result_tuple, 1, header_value_as_bytes);

        if (!wsgi_validate_header_value(header_value_as_bytes))
            goto failure;
    }

    return result;

failure:
    Py_DECREF(result);
    return NULL;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
