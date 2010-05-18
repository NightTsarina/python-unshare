/* vim:ts=4:sw=4:et:ai:sts=4
 *
 * python-unshare: Python bindings for the Linux unshare() syscall
 * Copyright © 2010 Martín Ferrari <martin.ferrari@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <Python.h>
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <sched.h>

static PyObject * _unshare(PyObject *self, PyObject *args) {
    int flags, ret;
    if (!PyArg_ParseTuple(args, "i", &flags))
        return NULL;
    ret = unshare(flags);
    if(ret == -1)
        return PyErr_SetFromErrno(PyExc_OSError);
    Py_RETURN_NONE;
}
static PyMethodDef methods[] = {
    {"unshare", _unshare, METH_VARARGS,
        "unshare(flags)\n\n"
        "Disassociate parts of the process execution context.\n"
        "flags is a bitmask that specifies which parts to unshare.\n\n"
        "Possible values for flags:\n"
        "  CLONE_VM CLONE_FS CLONE_FILES CLONE_SIGHAND CLONE_THREAD "
        "CLONE_NEWNS\n"
        "  CLONE_SYSVSEM CLONE_NEWUTS CLONE_NEWIPC CLONE_NEWUSER "
        "CLONE_NEWPID\n"
        "  CLONE_NEWNET\n"
    },
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initunshare(void) {
    PyObject *m;
    m = Py_InitModule("unshare", methods);
    if (m == NULL)
        return;

    /* Currently (2.6.33) not-implemented: CLONE_VM, CLONE_SIGHAND,
     * CLONE_THREAD, CLONE_NEWUSER, CLONE_NEWPID */

    PyModule_AddIntConstant(m, "CLONE_VM", CLONE_VM);
    /* No CAP_* needed */
    PyModule_AddIntConstant(m, "CLONE_FS", CLONE_FS);
    /* No CAP_* needed */
    PyModule_AddIntConstant(m, "CLONE_FILES", CLONE_FILES);
    PyModule_AddIntConstant(m, "CLONE_SIGHAND", CLONE_SIGHAND);
    PyModule_AddIntConstant(m, "CLONE_THREAD", CLONE_THREAD);
    /* CAP_SYS_ADMIN */
    PyModule_AddIntConstant(m, "CLONE_NEWNS", CLONE_NEWNS);
    PyModule_AddIntConstant(m, "CLONE_SYSVSEM", CLONE_SYSVSEM);
    /* CAP_SYS_ADMIN */
    PyModule_AddIntConstant(m, "CLONE_NEWUTS", CLONE_NEWUTS);
    /* CAP_SYS_ADMIN */
    PyModule_AddIntConstant(m, "CLONE_NEWIPC", CLONE_NEWIPC);
    PyModule_AddIntConstant(m, "CLONE_NEWUSER", CLONE_NEWUSER);
    PyModule_AddIntConstant(m, "CLONE_NEWPID", CLONE_NEWPID);
    /* CAP_SYS_ADMIN */
    PyModule_AddIntConstant(m, "CLONE_NEWNET", CLONE_NEWNET);
}

