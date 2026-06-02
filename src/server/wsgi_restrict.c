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

#include "wsgi_restrict.h"

#include "wsgi_module.h"

/* ------------------------------------------------------------------------- */

/*
 * Heap-type destructor. The instance holds no PyObject members
 * (just a borrowed C string), so there is no per-field cleanup.
 * Every heap-type instance carries an implicit reference to its
 * type, which the dealloc must release after freeing the instance
 * memory. tp_free is the type's allocator pair (default
 * PyObject_Free for a non-GC type) and is fetched from the type
 * itself rather than called directly so subclassing keeps working.
 */

static void Restricted_dealloc(RestrictedObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    tp->tp_free(self);
    Py_DECREF(tp);
}

/*
 * Attribute lookup hook installed as tp_getattro. Any access of
 * the form `obj.<anything>` lands here and raises OSError naming
 * the stream (e.g. "sys.stdin access restricted by mod_wsgi") so
 * the operator can identify the misuse from the traceback.
 */

static PyObject *Restricted_getattr(RestrictedObject *self,
                                    PyObject *Py_UNUSED(name))
{
    PyErr_Format(PyExc_OSError, "%s access restricted by mod_wsgi", self->s);

    return NULL;
}

/* ------------------------------------------------------------------------- */

/*
 * PyType_Spec for the Restricted heap type. Only the two slots
 * that have non-default behaviour are listed; everything else
 * (tp_alloc, tp_free, tp_repr, …) falls back to the framework
 * defaults that PyType_FromModuleAndSpec wires in.
 *
 * tp_name is "mod_wsgi.Restricted" so that error messages and
 * repr() output identify where the type comes from. The type is
 * not exposed as a `mod_wsgi.Restricted` attribute on the module
 * (it is purely an internal sentinel), so the qualified name is
 * for diagnostic purposes only.
 */

static PyType_Slot Restricted_slots[] = {
    {Py_tp_dealloc, Restricted_dealloc},
    {Py_tp_getattro, Restricted_getattr},
    {0, NULL},
};

static PyType_Spec Restricted_spec = {
    .name = "mod_wsgi.Restricted",
    .basicsize = sizeof(RestrictedObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = Restricted_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_restricted_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    /*
     * PyType_FromModuleAndSpec associates the resulting type with
     * `module` so that PyType_GetModule(type) returns the module.
     */

    type = PyType_FromModuleAndSpec(module, &Restricted_spec, NULL);
    if (!type)
        return -1;

    state->Restricted_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

RestrictedObject *newRestrictedObject(const char *s)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    RestrictedObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current interpreter
     * and pull the Restricted heap type out of its state. The
     * lookup is a sys.modules hit plus an INCREF, fast enough for
     * the few sites that construct Restricted instances (twice
     * per sub-interpreter, at init time).
     *
     * Returns NULL with a clear error if the module is not in
     * sys.modules or its state has not been initialised; either
     * indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Restricted_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Restricted type not initialised for the current "
                        "interpreter; newRestrictedObject() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Restricted_Type;

    /*
     * tp_alloc is the heap-type-aware allocator; it bumps the
     * type's refcount as well as zero-initialising the instance,
     * which is what allows Restricted_dealloc to do
     * Py_DECREF(Py_TYPE(self)) safely.
     */

    self = (RestrictedObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    self->s = s;

    return self;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
