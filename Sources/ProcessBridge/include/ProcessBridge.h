#ifndef PROCESS_BRIDGE_H
#define PROCESS_BRIDGE_H
#include <stdint.h>
typedef struct {
    uint32_t uid;
    int32_t parent;
    uint64_t start;
    char executable[4096];
    char directory[4096];
} PCIdentity;
int pc_identity(int32_t pid, PCIdentity *out);
int pc_arguments(int32_t pid, char *out, int capacity);
#endif
