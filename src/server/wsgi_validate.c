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

#include "wsgi_validate.h"

#include "wsgi_convert.h"

#include <ctype.h>

/* ------------------------------------------------------------------------- */

/*
 * A WSGI response status line consists of a status code and a reason
 * phrase separated by one or more space characters. The status code is
 * a 3 digit integer. The reason phrase is any text excluding control
 * characters and specifically excluding any carriage return or line
 * feed characters. Technically the reason phrase can be empty so long
 * as there still is at least a single space after the status code.
 */

int wsgi_validate_status_line(PyObject *value)
{
    const char *s;

    if (!PyBytes_Check(value)) {
        PyErr_Format(PyExc_TypeError, "expected byte string object for "
                     "status line, value of type %.200s found",
                     value->ob_type->tp_name);
        return 0;
    }
    
    s = PyBytes_AsString(value);

    if (!isdigit(*s++) || !isdigit(*s++) || !isdigit(*s++)) {
        PyErr_SetString(PyExc_ValueError,
                        "status code is not a 3 digit integer");
        return 0;
    }

    if (isdigit(*s)) {
        PyErr_SetString(PyExc_ValueError,
                        "status code is not a 3 digit integer");
        return 0;
    }

    if (*s != ' ') {
        PyErr_SetString(PyExc_ValueError, "no space following status code");
        return 0;
    }

    if (!*s) {
        PyErr_SetString(PyExc_ValueError, "no reason phrase supplied");
        return 0;
    }

    while (*s) {
        if (iscntrl(*s)) {
            PyErr_SetString(PyExc_ValueError,
                            "control character present in reason phrase");
            return 0;
        }
        s++;
    }

    return 1;
}

/* ------------------------------------------------------------------------- */

/*
 * A WSGI header name is a token consisting of one or more characters
 * except control characters, the separator characters "(", ")", "<",
 * ">", "@", ",", ";", ":", "\", <">, "/", "[", "]", "?", "=", "{", "}"
 * and the space character. Only bother checking for control characters
 * and space characters as it is only carriage return, line feed,
 * leading and trailing white space that are really a problem.
 */

int wsgi_validate_header_name(PyObject *value)
{
    const char *s;

    if (!PyBytes_Check(value)) {
        PyErr_Format(PyExc_TypeError, "expected byte string object for "
                     "header name, value of type %.200s found",
                     value->ob_type->tp_name);
        return 0;
    }
    
    s = PyBytes_AsString(value);

    if (!*s) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return 0;
    }

    while (*s) {
        if (iscntrl(*s)) {
            PyErr_SetString(PyExc_ValueError,
                            "control character present in header name");
            return 0;
        }

        if (*s == ' ') {
            PyErr_SetString(PyExc_ValueError,
                            "space character present in header name");
            return 0;
        }
        s++;
    }

    return 1;
}

/* ------------------------------------------------------------------------- */

/*
 * A WSGI header value consists of any number of characters except
 * control characters. Only bother checking for carriage return and line
 * feed characters as it is not possible to trust that applications will
 * not use control characters. In practice the intent is that WSGI
 * applications shouldn't use embedded carriage return and line feed
 * characters to prevent attempts at line continuation which may cause
 * problems with some hosting mechanisms. In other words, the header
 * value should be all on one line.
 */

int wsgi_validate_header_value(PyObject *value)
{
    const char *s;

    if (!PyBytes_Check(value)) {
        PyErr_Format(PyExc_TypeError, "expected byte string object for "
                     "header value, value of type %.200s found",
                     value->ob_type->tp_name);
        return 0;
    }
    
    s = PyBytes_AsString(value);

    while (*s) {
        if (*s == '\r' || *s == '\n') {
            PyErr_SetString(PyExc_ValueError, "carriage return/line "
                            "feed character present in header value");
            return 0;
        }
        s++;
    }

    return 1;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
