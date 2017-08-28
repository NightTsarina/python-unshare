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
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>

struct mapping {
    char **value;
    char *kw_name;
    int mask;
    char *mask_name;
    char *format;
    int is_mounted;
};

static struct mask_list_entry {
    char *name;
    int mask;
} mask_list[] = {
    { "CLONE_FILES",     CLONE_FILES },
    { "CLONE_FS",        CLONE_FS },
    { "CLONE_NEWCGROUP", CLONE_NEWCGROUP },
    { "CLONE_NEWIPC",    CLONE_NEWIPC },
    { "CLONE_NEWNET",    CLONE_NEWNET },
    { "CLONE_NEWNS",     CLONE_NEWNS },
    { "CLONE_NEWPID",    CLONE_NEWPID },
    { "CLONE_NEWUSER",   CLONE_NEWUSER },
    { "CLONE_NEWUTS",    CLONE_NEWUTS },
    { "CLONE_SIGHAND",   CLONE_SIGHAND },
    { "CLONE_SYSVSEM",   CLONE_SYSVSEM },
    { "CLONE_THREAD",    CLONE_THREAD },
    { "CLONE_VM",        CLONE_VM },
    { NULL,              0 }
};

static int ns_bind_mount(pid_t bpid, struct mapping *mapping) {
    return 0;
}

static PyObject * _unshare(PyObject *self, PyObject *args, PyObject *keywds)
{
    int ret;

    int v_flags = 0;
    static char *empty = "";
    char *v_cgroup = empty;
    char *v_ipc = empty;
    char *v_mount = empty;
    char *v_net = empty;
    char *v_pid = empty;
    char *v_user = empty;
    char *v_uts = empty;
    static char *kwlist[] = { "flags", "cgroup", "ipc", "mount", "net", "pid", "user", "uts", NULL };
    struct mapping mapping[] = {
        { NULL, kwlist[0], 0, NULL, NULL, 0 },
        { &v_cgroup, kwlist[1], CLONE_NEWCGROUP, "CLONE_NEWCGROUP", "/proc/%d/ns/cgroup", 0 },
        { &v_ipc, kwlist[2], CLONE_NEWIPC, "CLONE_NEWIPC", "/proc/%d/ns/ipc", 0 },
        { &v_mount, kwlist[3], CLONE_NEWNS, "CLONE_NEWNS", "/proc/%d/ns/mnt", 0 },
        { &v_net, kwlist[4], CLONE_NEWNET, "CLONE_NEWNET", "/proc/%d/ns/net", 0 },
        { &v_pid, kwlist[5], CLONE_NEWPID, "CLONE_NEWPID", "/proc/%d/ns/pid", 0 },
        { &v_user, kwlist[6], CLONE_NEWUSER, "CLONE_NEWUSER", "/proc/%d/ns/user", 0 },
        { &v_uts, kwlist[7], CLONE_NEWUTS, "CLONE_NEWUTS", "/proc/%d/ns/uts", 0 },
        { NULL, NULL, 0, NULL, NULL, 0 }
    };

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|izzzzzzz", kwlist,
                                     &v_flags, &v_cgroup, &v_ipc, &v_mount, &v_net, &v_pid, &v_user, &v_uts))
        return NULL;

    fprintf(stderr, "-- flags=%d cgroup=%s ipc=%s mount=%s net=%s pid=%s user=%s uts=%s\n",
            v_flags, v_cgroup, v_ipc, v_mount, v_net, v_pid, v_user, v_uts);

    /* Sanity check parameters and collect bind info */
    struct mapping * m;
    int needed_mounts = 0;
    int flags = v_flags;
    for ( m = mapping + 1 ; m->value ; m++) {;
        if (*m->value != empty) {
            flags |= m->mask;
            if (*m->value) needed_mounts++;
            if ((v_flags != 0) && ((v_flags & m->mask) == 0)) {
                char msg[1024];
                snprintf(msg, sizeof msg, "%s keyword given, but %s (%x) not in flags (%x)",
                         m->kw_name, m->mask_name, m->mask, v_flags);
                PyErr_SetString(PyExc_OSError, msg);
                return NULL;
            }
        }
    }

    if (needed_mounts == 0) {
        /* Simple case */
        ret = unshare(flags);
        if (ret == -1)
            return PyErr_SetFromErrno(PyExc_OSError);
    } else {
        /* Check that only restorable namespaces are specified when needing bind mounts */
        if (needed_mounts >= 0) {
            int bind_flags = 0;
            pid_t pid = getpid();
            for ( m = mapping + 1 ; m->value ; m++) {
                char ns[PATH_MAX];
                struct stat stat_buf;
                snprintf(ns, sizeof(ns), m->format, pid);
                if (stat(ns, &stat_buf) == 0) {
                    bind_flags |= m->mask;
                }
            }
            int bad = flags & ~bind_flags;
            if (bad != 0) {
                int pos = 0;
                char msg[PATH_MAX];
                struct mask_list_entry *ml;

                ret = snprintf(msg, sizeof(msg),  "Unrestorable namespace detected [ ");
                if (ret < 0)
                    return PyErr_SetFromErrno(PyExc_OSError);
                pos = ret;
                for (ml = mask_list ; ml->name ; ml++) {
                    if (bad & ml->mask) {
                        ret = snprintf(msg + pos, sizeof(msg) - pos,  " %s |", ml->name);
                        if (ret < 0)
                            return PyErr_SetFromErrno(PyExc_OSError);
                        pos += ret;
                    }
                }
                ret = snprintf(msg + pos - 1, sizeof(msg) - pos + 1,  "] when saving namespace");
                if (ret < 0)
                    return PyErr_SetFromErrno(PyExc_OSError);
                PyErr_SetString(PyExc_OSError, msg);
                return NULL;
            }
        }
        fprintf(stderr, "XXX\n");
        int fd[2];
        ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        if(ret == -1)
            return PyErr_SetFromErrno(PyExc_OSError);
        pid_t pid = fork();
        if (pid < 0) {
            close(fd[0]);
            close(fd[1]);
            return PyErr_SetFromErrno(PyExc_OSError);
        } else if (pid == 0) {
            /* Child */
            close(fd[1]);
            unsigned char result = 0;
            ret = unshare(flags);
            if (ret != 0) {
                result = errno < 255 ? errno : EINVAL;
            }
            if (write(fd[0], &result, 1) != 1) {
                exit(1);
            }
            ret = read(fd[0], &result, 1);
            fprintf(stderr, "EXIT %d %d\n", result, ret);
            if (ret != 1 || result != 'Q') {
                exit(1);
            }
            exit(0);
        } else {
            /* Parent */
            unsigned char result;

            close(fd[0]);
            ret = read(fd[1], &result, 1);
            if (ret == -1) {
                close(fd[1]);
                return PyErr_SetFromErrno(PyExc_OSError);
            }
            if (result != 0) {
                errno = result;
                return PyErr_SetFromErrno(PyExc_OSError);
            }
            fprintf(stderr, "MOUNT %d\n", result);
            for ( m = mapping + 1 ; m->value ; m++) {;
                if (*m->value != NULL && *m->value != empty) {

                    char ns[PATH_MAX];
                    snprintf(ns, sizeof(ns), m->format, pid);
                    fprintf(stderr, "BIND %s %s\n", ns, *m->value);
                    ret = mount(ns, *m->value, NULL, MS_BIND, NULL);
                    if (ret == -1) {
                        close(fd[1]);
                        fprintf(stderr, "TODO cleanup succeded mounts");
                        return PyErr_SetFromErrno(PyExc_OSError);
                    } else {
                        m->is_mounted = 1;
                    }
                }
            }
            fprintf(stderr, "NSENTER %d\n", result);
            for ( m = mapping + 1 ; m->value ; m++) {
                if (v_flags & m->mask) {
                    char ns[PATH_MAX];
                    int fd;
                    snprintf(ns, sizeof(ns), m->format, pid);
                    fd = open(ns, O_RDONLY);
                    ret = setns(fd, m->mask);
                    close(fd);
                    if (ret == -1)
                        return PyErr_SetFromErrno(PyExc_OSError);
                }
            }
           
            if (write(fd[1], "Q", 1) != 1) {
                close(fd[1]);
                return PyErr_SetFromErrno(PyExc_OSError);
            }
            close(fd[1]);
            wait(pid);
        }
    }
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
    {"unshare", (PyCFunction)_unshare, METH_VARARGS | METH_KEYWORDS,
     "unshare(flags, **kwargs)\n\n"
     "Disassociate parts of the process execution context.\n"
     "flags is a bitmask that specifies which parts to unshare.\n\n"
     "Possible values for flags:\n"
     "  CLONE_VM CLONE_FS CLONE_FILES CLONE_SIGHAND CLONE_THREAD "
     "CLONE_NEWNS\n"
     "  CLONE_SYSVSEM CLONE_NEWUTS CLONE_NEWIPC CLONE_NEWUSER "
     "CLONE_NEWPID\n"
     "  CLONE_NEWNET\n"
    },
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
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initunshare(void) {
    PyObject *m;
    m = Py_InitModule("unshare", methods);
    if (m == NULL)
        return;

    struct mask_list_entry *ml;

    for (ml = mask_list ; ml->name ; ml++) {
        PyModule_AddIntConstant(m, ml->name, ml->mask);
    }
}

