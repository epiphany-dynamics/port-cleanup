#include "ProcessBridge.h"
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>
#include <sys/sysctl.h>
#include <stdlib.h>

// Copy argv only. Never copy the environment following it in KERN_PROCARGS2.
int pc_arguments(int32_t pid, char *out, int capacity) {
    size_t size = 0; int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size > 1048576 || size < sizeof(int)) return -1;
    char *buffer = calloc(1, size);
    if (!buffer) return -1;
    if (sysctl(mib, 3, buffer, &size, NULL, 0) != 0) { free(buffer); return -1; }
    int argc = 0; memcpy(&argc, buffer, sizeof(int));
    char *p = buffer + sizeof(int), *end = buffer + size;
    while (p < end && *p) p++;
    while (p < end && !*p) p++;
    int used = 0;
    for (int i = 0; i < argc && p < end; i++) {
        size_t n = strnlen(p, (size_t)(end - p));
        if (p + n >= end || n + 1 > (size_t)(capacity - used)) { used = -1; break; }
        memcpy(out + used, p, n + 1); used += (int)n + 1; p += n + 1;
    }
    volatile char *wipe = buffer;
    for (size_t i = 0; i < size; i++) wipe[i] = 0;
    free(buffer); return used;
}
int pc_identity(int32_t pid, PCIdentity *out) {
    struct proc_bsdinfo info = {0};
    memset(out, 0, sizeof(*out));
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 0;
    out->uid = info.pbi_uid;
    out->parent = (int32_t)info.pbi_ppid;
    out->start = info.pbi_start_tvsec * 1000000ULL + info.pbi_start_tvusec;
    if (proc_pidpath(pid, out->executable, sizeof(out->executable)) <= 0) return 0;
    struct proc_vnodepathinfo paths = {0};
    if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &paths, sizeof(paths)) == sizeof(paths))
        strlcpy(out->directory, paths.pvi_cdir.vip_path, sizeof(out->directory));
    return 1;
}
