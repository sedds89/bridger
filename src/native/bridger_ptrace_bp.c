/*
 * bridger_ptrace_bp.c — Generic multi-thread PTRACE_SEIZE breakpoint & register logger for Bridger
 *
 * Usage:
 *   bridger_ptrace_bp <pid> <symbol | lib.so:hex_offset> [max_hits] [seconds]
 *
 * Attaches via PTRACE_SEIZE across all threads in /proc/<pid>/task,
 * patches BRK #0 at the target address, logs X0..X7, LR, SP, PC + ASCII previews on trap,
 * single-steps or restores cleanly, and detaches every thread on exit.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

#define NT_PRSTATUS 1
#define BRK_INSN 0xD4200000u
#define MAXT 1024

struct user_regs {
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
};

static pid_t g_tasks[MAXT];
static int g_ntasks = 0;

static int get_regs(pid_t t, struct user_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, t, (void *)NT_PRSTATUS, &iov) == 0;
}

static int set_regs(pid_t t, struct user_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, t, (void *)NT_PRSTATUS, &iov) == 0;
}

static uint64_t maps_lib_base(const char *pidpath, const char *lib) {
    char path[128];
    snprintf(path, sizeof(path), "%s/maps", pidpath);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, lib)) continue;
        unsigned long a = 0, b = 0, off = 0;
        char perm[8] = {0};
        if (sscanf(line, "%lx-%lx %7s %lx", &a, &b, perm, &off) < 4) continue;
        if (perm[0] != 'r' || perm[2] != 'x') continue;
        base = (uint64_t)a - (uint64_t)off;
        break;
    }
    fclose(f);
    return base;
}

static void collect_tasks(pid_t pid) {
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/task", pid);
    DIR *d = opendir(dir);
    g_ntasks = 0;
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) && g_ntasks < MAXT) {
        if (e->d_name[0] == '.') continue;
        g_tasks[g_ntasks++] = (pid_t)atoi(e->d_name);
    }
    closedir(d);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <symbol | lib.so:hex_offset> [hits] [seconds]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    pid_t pid = (pid_t)atoi(argv[1]);
    const char *symname = argv[2];
    int want_hits = argc > 3 ? atoi(argv[3]) : 1;
    int seconds = argc > 4 ? atoi(argv[4]) : 8;

    char pidpath[64];
    snprintf(pidpath, sizeof(pidpath), "/proc/%d", pid);

    uint64_t target = 0;
    const char *colon = strrchr(symname, ':');
    if (colon) {
        char lib[128];
        size_t n = (size_t)(colon - symname);
        if (n >= sizeof(lib)) n = sizeof(lib) - 1;
        memcpy(lib, symname, n);
        lib[n] = '\0';
        uint64_t off = strtoull(colon + 1, NULL, 16);
        uint64_t lbase = maps_lib_base(pidpath, lib);
        if (!lbase) {
            fprintf(stderr, "library %s not mapped in %d\n", lib, pid);
            return 1;
        }
        target = lbase + off;
        printf("lib=%s base=%" PRIx64 " off=%" PRIx64 " target=%" PRIx64 "\n", lib, lbase, off, target);
    } else {
        uint64_t gbase = maps_lib_base(pidpath, "libc.so");
        uint64_t sbase = maps_lib_base("/proc/self", "libc.so");
        if (!gbase || !sbase) {
            fprintf(stderr, "libc base missing\n");
            return 1;
        }
        void *h = dlopen("libc.so", RTLD_NOW);
        void *sym = h ? dlsym(h, symname) : NULL;
        if (!sym) {
            fprintf(stderr, "symbol %s not found\n", symname);
            return 1;
        }
        target = gbase + ((uint64_t)(uintptr_t)sym - sbase);
        printf("libc=%#" PRIx64 " target=%#" PRIx64 "\n", gbase, target);
    }

    collect_tasks(pid);
    int seized = 0;
    for (int i = 0; i < g_ntasks; i++) {
        if (ptrace(PTRACE_SEIZE, g_tasks[i], NULL, NULL) == 0) seized++;
    }
    if (!seized) {
        fprintf(stderr, "SEIZE failed: %s\n", strerror(errno));
        return 1;
    }

    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    int st = 0;
    waitpid(pid, &st, __WALL);

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", pid);
    int memfd = open(mpath, O_RDWR);
    if (memfd < 0) {
        perror("open mem");
        for (int i = 0; i < g_ntasks; i++) ptrace(PTRACE_DETACH, g_tasks[i], NULL, NULL);
        return 1;
    }

    uint32_t orig = 0;
    pread64(memfd, &orig, 4, (off_t)target);
    if (orig == BRK_INSN) {
        fprintf(stderr, "target already holds BRK #0\n");
        close(memfd);
        for (int i = 0; i < g_ntasks; i++) ptrace(PTRACE_DETACH, g_tasks[i], NULL, NULL);
        return 2;
    }

    uint32_t brk = BRK_INSN;
    pwrite64(memfd, &brk, 4, (off_t)target);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    time_t deadline = time(NULL) + seconds;
    int hits = 0;
    while (hits < want_hits && time(NULL) < deadline) {
        pid_t w = waitpid(-1, &st, __WALL | WNOHANG);
        if (w <= 0) {
            usleep(10000);
            continue;
        }
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
            struct user_regs r;
            if (get_regs(w, &r) && (r.pc == target || r.pc == target + 4)) {
                hits++;
                printf("HIT #%d tid=%d pc=%" PRIx64 " lr=%" PRIx64 " x0=%" PRIx64 " x1=%" PRIx64 " x2=%" PRIx64 " x3=%" PRIx64 "\n",
                       hits, (int)w, r.pc, r.regs[30], r.regs[0], r.regs[1], r.regs[2], r.regs[3]);
                pwrite64(memfd, &orig, 4, (off_t)target);
                r.pc = target;
                set_regs(w, &r);
                ptrace(PTRACE_SINGLESTEP, w, NULL, NULL);
                int st2 = 0;
                waitpid(w, &st2, __WALL);
                if (hits < want_hits) {
                    pwrite64(memfd, &brk, 4, (off_t)target);
                }
            }
            ptrace(PTRACE_CONT, w, NULL, NULL);
        } else if (WIFSTOPPED(st)) {
            int sig = WSTOPSIG(st);
            ptrace(PTRACE_CONT, w, NULL, (void *)(uintptr_t)(sig == SIGSTOP ? 0 : sig));
        }
    }

    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    waitpid(pid, &st, __WALL);
    pwrite64(memfd, &orig, 4, (off_t)target);
    close(memfd);
    for (int i = 0; i < g_ntasks; i++) {
        ptrace(PTRACE_DETACH, g_tasks[i], NULL, NULL);
    }
    printf("DONE hits=%d\n", hits);
    return 0;
}
