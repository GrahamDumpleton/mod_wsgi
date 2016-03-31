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

#include "wsgi_buckets.h"

#include "wsgi_interp.h"

/* ------------------------------------------------------------------------- */

typedef struct {
    apr_bucket_refcount  refcount;
    char *base;
    const char *application_group;
    PyObject *string_object;
    int decref_string;
} wsgi_apr_bucket_python;

/* ------------------------------------------------------------------------- */

static void wsgi_python_bucket_destroy(void *data)
{
    wsgi_apr_bucket_python *h = data;

    if (apr_bucket_shared_destroy(h)) {
        if (h->decref_string) {
            InterpreterObject *interp = NULL;

            interp = wsgi_acquire_interpreter(h->application_group);
            Py_DECREF(h->string_object);
            wsgi_release_interpreter(interp);
        }

        apr_bucket_free(h);
    }
}

/* ------------------------------------------------------------------------- */

static apr_status_t wsgi_python_bucket_read(apr_bucket *b, const char **str,
                                            apr_size_t *len,
                                            apr_read_type_e block)
{
    wsgi_apr_bucket_python *h = b->data;

    *str = h->base + b->start;
    *len = b->length;
    return APR_SUCCESS;
}

/* ------------------------------------------------------------------------- */

static apr_bucket *wsgi_apr_bucket_python_make(apr_bucket *b,
                                               const char *buf,
                                               apr_size_t length,
                                               const char *application_group,
                                               PyObject *string_object,
                                               int decref_string
                                               )
{
    wsgi_apr_bucket_python *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);

    h->base = (char *)buf;
    h->application_group = application_group;
    h->string_object = string_object;
    h->decref_string = decref_string;

    b = apr_bucket_shared_make(b, h, 0, length);
    b->type = &wsgi_apr_bucket_type_python;

    return b;
}

/* ------------------------------------------------------------------------- */

apr_bucket *wsgi_apr_bucket_python_create(const char *buf, apr_size_t length,
                                          const char *application_group,
                                          PyObject *string_object,
                                          apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;

    return wsgi_apr_bucket_python_make(b, buf, length, application_group,
            string_object, 0);
}

/* ------------------------------------------------------------------------- */

static apr_status_t wsgi_python_bucket_setaside(apr_bucket *b, apr_pool_t *p)
{
    wsgi_apr_bucket_python *h = b->data;

    if (h->decref_string) {
        /*
         * XXX Not sure if this is correct. Can't assume that if doing
         * a set aside of a bucket which was already set aside that
         * we aren't still in context of active interpreter.
         */
        InterpreterObject *interp = NULL;

        interp = wsgi_acquire_interpreter(h->application_group);
        Py_INCREF(h->string_object);
        wsgi_release_interpreter(interp);
    }
    else {
        Py_INCREF(h->string_object);
    }

    wsgi_apr_bucket_python_make(b, (char *)h->base + b->start, b->length,
            h->application_group, h->string_object, 1);

    return APR_SUCCESS;
}

/* ------------------------------------------------------------------------- */

const apr_bucket_type_t wsgi_apr_bucket_type_python = {
    "PYTHON", 5, APR_BUCKET_DATA,
    wsgi_python_bucket_destroy,
    wsgi_python_bucket_read,
    wsgi_python_bucket_setaside,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
