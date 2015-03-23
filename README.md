This simple extension provides bindings to the Linux `unshare()` syscall, added in kernel version 2.6.16

By using `unshare()`, new and interesting features of the Linux kernel can be exploited, such as:

 * Creating a new network name space (`CLONE_NEWNET`)
 * Creating a new file system mount name space (`CLONE_NEWNS`)
 * Reverting other features shared from `clone()`

This library provides an equivalent of the (recently added) util-linux command-line program `unshare`.
