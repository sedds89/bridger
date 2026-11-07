/*
 * bridger_memtool.c — Standalone multipurpose arm64 CLI memory utility for Bridger
 *
 * Subcommands:
 *   bridger_memtool pidof <package>
 *   bridger_memtool maps  <pid> [substring]
 *   bridger_memtool find  <pid> [--u16] <pattern> [max_hits]
 *   bridger_memtool dump  <pid> <hex_addr> <length> <out_file>
 *   bridger_memtool poke  <pid> <hex_addr> <hex_bytes>
 *   bridger_memtool redir <pid> <old_str> <new_str>
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

typedef struct {
    uint64_t lo, hi;
    char perm[8];
    char path[256];
} Seg;

static Seg g_segs[8192];
static int g_nseg = 0;

static void load_maps(int pid) {
    g_nseg = 0;
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) {
        perror("fopen maps");
        return;
    }
    char line[1024];
    while (g_nseg < 8192 && fgets(line, sizeof(line), f)) {
        unsigned long lo = 0, hi = 0;
        char perm[8] = {0};
        int pos = 0;
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %n", &lo, &hi, perm, &pos) < 3) continue;
        g_segs[g_nseg].lo = lo;
        g_segs[g_nseg].hi = hi;
        strncpy(g_segs[g_nseg].perm, perm, 7);
        g_segs[g_nseg].path[0] = '\0';
        if (pos > 0 && line[pos]) {
            char *s = line + pos;
            while (*s == ' ' || *s == '\t') s++;
            size_t l = strlen(s);
            while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r')) s[--l] = '\0';
            strncpy(g_segs[g_nseg].path, s, sizeof(g_segs[g_nseg].path) - 1);
        }
        g_nseg++;
    }
    fclose(f);
}

static int parse_hex(const char *s, uint8_t *out, int max_len) {
    int n = 0;
    while (*s && n < max_len) {
        unsigned v = 0;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static ssize_t safe_write(int pid, int fd, const void *buf, size_t len, uint64_t addr) {
    ssize_t w = pwrite64(fd, buf, len, (off_t)addr);
    if (w == (ssize_t)len) return w;
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == 0) {
        if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == 0) {
            int st = 0;
            waitpid(pid, &st, __WALL);
        }
        w = pwrite64(fd, buf, len, (off_t)addr);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
        int st = 0;
        waitpid(pid, &st, 0);
        w = pwrite64(fd, buf, len, (off_t)addr);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    return w;
}

static int cmd_pidof(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) return 1;
    struct dirent *de;
    int my_pid = (int)getpid();
    while ((de = readdir(d)) != NULL) {
        int pid = atoi(de->d_name);
        if (pid <= 0 || pid == my_pid) continue;
        char p[64], cmd[256] = {0};
        snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n > 0 && strcmp(cmd, pkg) == 0) {
            printf("%d\n", pid);
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "Usage:\n"
                "  %s pidof <package>\n"
                "  %s maps  <pid> [substring]\n"
                "  %s find  <pid> [--u16] <pattern> [max_hits]\n"
                "  %s dump  <pid> <hex_addr> <length> <out_file>\n"
                "  %s poke  <pid> <hex_addr> <hex_bytes>\n"
                "  %s redir <pid> <old_str> <new_str>\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }

    const char *sub = argv[1];
    if (strcmp(sub, "pidof") == 0) {
        return cmd_pidof(argv[2]);
    }

    int pid = atoi(argv[2]);
    load_maps(pid);

    if (strcmp(sub, "maps") == 0) {
        const char *want = argc > 3 ? argv[3] : NULL;
        int found = 0;
        for (int i = 0; i < g_nseg; i++) {
            if (want && strstr(g_segs[i].path, want) == NULL) continue;
            printf("BASE %" PRIx64 " END %" PRIx64 " SIZE %" PRIx64 " PERM %s PATH %s\n",
                   g_segs[i].lo, g_segs[i].hi, g_segs[i].hi - g_segs[i].lo,
                   g_segs[i].perm, g_segs[i].path);
            found++;
        }
        return found ? 0 : 1;
    }

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", pid);

    if (strcmp(sub, "dump") == 0 && argc >= 6) {
        uint64_t addr = strtoull(argv[3], NULL, 0);
        size_t len = (size_t)strtoull(argv[4], NULL, 0);
        const char *out_path = argv[5];
        int fd = open(mpath, O_RDONLY);
        if (fd < 0) { perror("open mem"); return 1; }
        FILE *out = fopen(out_path, "wb");
        if (!out) { perror("fopen out"); close(fd); return 1; }
        uint8_t buf[65536];
        size_t left = len;
        uint64_t cur = addr;
        while (left > 0) {
            size_t step = left > sizeof(buf) ? sizeof(buf) : left;
            ssize_t got = pread64(fd, buf, step, (off_t)cur);
            if (got <= 0) break;
            fwrite(buf, 1, (size_t)got, out);
            cur += (uint64_t)got;
            left -= (size_t)got;
        }
        fclose(out);
        close(fd);
        printf("DUMPED %zu\n", len - left);
        return (left == 0) ? 0 : 1;
    }

    if (strcmp(sub, "poke") == 0 && argc >= 5) {
        uint64_t addr = strtoull(argv[3], NULL, 0);
        uint8_t bytes[1024];
        int n = parse_hex(argv[4], bytes, sizeof(bytes));
        int fd = open(mpath, O_RDWR);
        if (fd < 0) { perror("open mem rw"); return 1; }
        ssize_t w = safe_write(pid, fd, bytes, (size_t)n, addr);
        close(fd);
        printf("WRITE %d at %" PRIx64 " -> %zd\n", n, addr, w);
        return (w == n) ? 0 : 1;
    }

    if (strcmp(sub, "find") == 0 && argc >= 4) {
        int u16 = 0;
        int argi = 3;
        if (strcmp(argv[argi], "--u16") == 0 && argc >= 5) {
            u16 = 1;
            argi++;
        }
        const char *pat = argv[argi++];
        int max_hits = (argi < argc) ? atoi(argv[argi]) : 32;
        size_t plen = strlen(pat);
        uint8_t *needle = (uint8_t *)malloc(plen * 2 + 2);
        if (u16) {
            for (size_t i = 0; i < plen; i++) { needle[2 * i] = (uint8_t)pat[i]; needle[2 * i + 1] = 0; }
            plen *= 2;
        } else {
            memcpy(needle, pat, plen);
        }
        int fd = open(mpath, O_RDONLY);
        if (fd < 0) { perror("open mem"); free(needle); return 1; }
        const size_t CH = 2 << 20;
        uint8_t *buf = (uint8_t *)malloc(CH + plen + 64);
        int hits = 0;
        for (int i = 0; i < g_nseg && hits < max_hits; i++) {
            if (g_segs[i].perm[0] != 'r') continue;
            uint64_t slen = g_segs[i].hi - g_segs[i].lo;
            if (slen < plen || slen > (512ULL << 20)) continue;
            for (uint64_t off = 0; off < slen && hits < max_hits; off += CH) {
                size_t want = (slen - off) > (CH + plen) ? (CH + plen) : (size_t)(slen - off);
                ssize_t got = pread64(fd, buf, want, (off_t)(g_segs[i].lo + off));
                if (got < (ssize_t)plen) break;
                for (size_t k = 0; k + plen <= (size_t)got && hits < max_hits; k++) {
                    if (buf[k] != needle[0]) continue;
                    if (memcmp(buf + k, needle, plen) != 0) continue;
                    printf("HIT %" PRIx64 " SEG %" PRIx64 "-%" PRIx64 " PERM %s\n",
                           g_segs[i].lo + off + k, g_segs[i].lo, g_segs[i].hi, g_segs[i].perm);
                    hits++;
                    k += plen - 1;
                }
            }
        }
        free(buf);
        free(needle);
        close(fd);
        return hits ? 0 : 1;
    }

    if (strcmp(sub, "redir") == 0 && argc >= 5) {
        const char *old_s = argv[3];
        const char *new_s = argv[4];
        size_t slen = strlen(old_s);
        size_t nlen = strlen(new_s);
        if (slen == 0 || nlen > slen) {
            fprintf(stderr, "new_str length (%zu) must be <= old_str length (%zu)\n", nlen, slen);
            return 2;
        }
        uint8_t *a_old = (uint8_t *)malloc(slen), *a_new = (uint8_t *)malloc(slen);
        uint8_t *u_old = (uint8_t *)malloc(slen * 2), *u_new = (uint8_t *)malloc(slen * 2);
        for (size_t i = 0; i < slen; i++) {
            uint8_t co = (uint8_t)old_s[i];
            uint8_t cn = (i < nlen) ? (uint8_t)new_s[i] : (uint8_t)'/';
            a_old[i] = co; a_new[i] = cn;
            u_old[2 * i] = co; u_old[2 * i + 1] = 0;
            u_new[2 * i] = cn; u_new[2 * i + 1] = 0;
        }
        int fd = open(mpath, O_RDWR);
        if (fd < 0) { perror("open mem rw"); return 1; }
        const size_t CH = 4 << 20;
        uint8_t *buf = (uint8_t *)malloc(CH + slen * 2 + 64);
        int patched = 0;
        for (int i = 0; i < g_nseg; i++) {
            int is_meta = strstr(g_segs[i].path, "global-metadata.dat") != NULL;
            if (g_segs[i].perm[0] != 'r') continue;
            if (g_segs[i].perm[1] != 'w' && !is_meta) continue;
            uint64_t slen_seg = g_segs[i].hi - g_segs[i].lo;
            if (slen_seg < slen || slen_seg > (512ULL << 20)) continue;
            for (uint64_t off = 0; off < slen_seg; off += CH) {
                size_t want = (slen_seg - off) > (CH + slen * 2) ? (CH + slen * 2) : (size_t)(slen_seg - off);
                ssize_t got = pread64(fd, buf, want, (off_t)(g_segs[i].lo + off));
                if (got < (ssize_t)slen) break;
                for (size_t k = 0; k + slen <= (size_t)got; k++) {
                    if (buf[k] != a_old[0] || memcmp(buf + k, a_old, slen) != 0) continue;
                    uint64_t at = g_segs[i].lo + off + k;
                    if (safe_write(pid, fd, a_new, slen, at) == (ssize_t)slen) {
                        printf("PATCH ascii %" PRIx64 "\n", at);
                        patched++;
                    }
                    k += slen - 1;
                }
                size_t ulen = slen * 2;
                for (size_t k = 0; k + ulen <= (size_t)got; k++) {
                    if (buf[k] != u_old[0] || buf[k + 1] != 0 || memcmp(buf + k, u_old, ulen) != 0) continue;
                    uint64_t at = g_segs[i].lo + off + k;
                    if (safe_write(pid, fd, u_new, ulen, at) == (ssize_t)ulen) {
                        printf("PATCH utf16 %" PRIx64 "\n", at);
                        patched++;
                    }
                    k += ulen - 1;
                }
            }
        }
        free(buf);
        free(a_old); free(a_new); free(u_old); free(u_new);
        close(fd);
        printf("TOTAL_PATCHED %d\n", patched);
        return patched > 0 ? 0 : 1;
    }

    return 2;
}
