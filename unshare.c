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

static PyObject * _setns(PyObject *self, PyObject *args) {
    int fd, nstype, ret;
    if (!PyArg_ParseTuple(args, "ii", &fd, &nstype))
        return NULL;
    ret = setns(fd, nstype);
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
#if __GLIBC_MINOR__ >= 14
    {"setns", _setns, METH_VARARGS,
        "setns(fd, nstype)\n\n"
        "Reassociate the calling thread with a new namespace.\n"
        "fd is a filedescriptor referring to a namespace.\n"
        "nstype specifies which type of namespace the calling thread\n"
        "may be reassociated with.\n\n"
        "Possible values for nstype:\n"
        "  0             Allow any type of namespace to be joined.\n"
        "  CLONE_NEWIPC  fd must refer to an IPC namespace.\n"
        "  CLONE_NEWNET  fd must refer to a network namespace.\n"
        "  CLONE_NEWNS   fd must refer to a mount namespace.\n"
        "  CLONE_NEWPID  fd must refer to a descendant PID namespace.\n"
        "  CLONE_NEWUSER fd must refer to a user namespace.\n"
        "  CLONE_NEWUTS  fd must refer to a UTS namespace.\n"
    },
#endif
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef =
{
	PyModuleDef_HEAD_INIT,
	"unshare", /* name of module */
	"",          /* module documentation, may be NULL */
	-1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
	methods
};
#endif

#if PY_MAJOR_VERSION >= 3
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
#else
#define MOD_INIT(name) PyMODINIT_FUNC init##name(void)
#endif

MOD_INIT(unshare) {
    PyObject *m;

    #if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&moduledef);
    if (m == NULL)
        return NULL;
    #else
    m = Py_InitModule3("unshare", methods, "");
    if (m == NULL)
        return;
    #endif

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

    #if PY_MAJOR_VERSION >= 3
    return m;
    #endif
}

