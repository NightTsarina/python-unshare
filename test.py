#!/usr/bin/python

import unshare
import time
import sys
import os
import itertools
import pickle

kw_ns = dict(cgroup=unshare.CLONE_NEWCGROUP,
             ipc=unshare.CLONE_NEWIPC,
             mount=unshare.CLONE_NEWNS,
             net=unshare.CLONE_NEWNET,
             pid=unshare.CLONE_NEWPID,
             user=unshare.CLONE_NEWUSER,
             uts=unshare.CLONE_NEWUTS)

flag_ns = (unshare.CLONE_FILES,
           unshare.CLONE_FS,
           unshare.CLONE_NEWCGROUP,
           unshare.CLONE_NEWIPC,
           unshare.CLONE_NEWNET,
           unshare.CLONE_NEWNS,
           unshare.CLONE_NEWPID,
           unshare.CLONE_NEWUSER,
           unshare.CLONE_NEWUTS,
           unshare.CLONE_SIGHAND,
           unshare.CLONE_SYSVSEM,
           unshare.CLONE_THREAD,
           unshare.CLONE_VM)

def test(v):
    flags = 0
    kwpath = {}
    for a in v:
        if len(a) == 1:
            flags |= a[0]
        else:
            kwpath[a[0]] = a[1];
    for k in kwpath:
        if os.path.exists(kwpath[k]) and unshare.get_nstype(kwpath[k]) != None:
            unshare.unbind(kwpath[k], kw_ns[k])
        open(kwpath[k], "w").close()
    r,w = os.pipe()
    r = os.fdopen(r)
    w = os.fdopen(w, 'w')
    pid = os.fork()
    if pid != 0:
        w.close()
        ns1 = pickle.load(r)
        ns2 = dict([ (k, os.stat("/proc/self/ns/%s" % (k)).st_ino)
                     for k in os.listdir("/proc/self/ns") ])
        pid, status = os.waitpid(pid, 0)
        if status != 0:
            print "%x %s failed" % (flags, kwpath)
            raise(Exception)
        else:
            for k in ns1:
                if k == 'pid':
                    continue
                def getpath():
                    if k in kwpath:
                        return kwpath[k]
                    if k == 'mnt' and 'mount' in kwpath:
                        return kwpath['mount']
                    if k == 'pid_for_children' and 'pid' in kwpath:
                        return kwpath['pid']
                    return None
                def getflags():
                    if k in kw_ns:
                        return kw_ns[k]
                    if k == 'mnt':
                        return kw_ns['mount']
                    if k == 'pid_for_children':
                        return kw_ns['pid']
                    raise Exception(k)
                path = getpath()
                def error(msg):
                    raise Exception("%s \n  %s \n  %s \n%x %s" % (
                        msg, ns1, ns2, flags, kwpath))
                if path != None:
                    if ns1[k] != os.stat(path).st_ino:
                        error("Wrong namespace saved in %s %d" % (
                            path, os.stat(path).st_ino))
                    if ns1[k] == ns2[k]:
                        raise Exception("%s %s %s" % (k, ns1, ns2))
                elif getflags() & flags == 0:
                    if ns1[k] != ns2[k]:
                        error("Namespaces not equal %s" % (k))
                else:
                     if ns1[k] == ns2[k]:
                        error("Namespaces equal %s" % (k))
    else:
        r.close()
        try:
            unshare.unshare(flags, **kwpath)
            ns = dict([ (k, os.stat("/proc/self/ns/%s" % (k)).st_ino)
                        for k in os.listdir("/proc/self/ns") ])
            pickle.dump(ns, w)
            w.close()
            os._exit(0)
        except Exception, e:
            print>>sys.stderr, e
            raise
            os._exit(1)
        
if __name__ == '__main__':
    args = list([ (n, os.path.join(sys.argv[1], n)) for n in kw_ns ] +
            [ (n,) for n in flag_ns ])
    if len(sys.argv) >=3:
        N = int(sys.argv[2])
    else:
        N = len(args)
    unshare.unshare(unshare.CLONE_NEWNS) # Isolate test from systemd
    for n in range(1, N + 1):
        combinations = list(itertools.combinations(args, n))
        print "n=%d/N=%d (%d combinations)" % (n, N, len(combinations))
        for v in combinations:
            try:
                test(v)
            except:
                print "test(%s) failed" % (str(v))
                raise
