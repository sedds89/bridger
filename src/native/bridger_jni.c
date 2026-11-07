/*
 * bridger_jni.c — Native multi-purpose cross-process engine for Bridger (libbridger.so)
 *
 * Provides JNI methods for:
 *   1. Finding PIDs by package/process name via /proc/<pid>/cmdline
 *   2. Reading full, untruncated /proc/<pid>/maps via sequential fgets()
 *   3. Reading & dumping process memory via /proc/<pid>/mem (pread64)
 *   4. Writing & patching process memory via /proc/<pid>/mem (pwrite64), with
 *      automatic PTRACE_SEIZE + PTRACE_INTERRUPT fallback when the kernel requires
 *      tracer attachment for same-UID /proc/<pid>/mem writes
 *   5. Fast native chunked memory scanning (ASCII, UTF-16LE, or raw bytes)
 *   6. In-memory string/endpoint redirection across all rw-p segments (ASCII + UTF-16LE)
 *      and segment-size + offset targets (ASLR-safe)
 */
#define _GNU_SOURCE
#include <jni.h>
#include <android/log.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "BridgerNative", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "BridgerNative", __VA_ARGS__)

typedef struct {
    uint64_t lo;
    uint64_t hi;
    char perm[8];
    uint64_t offset;
    char path[256];
} MapEntry;

static int parse_maps_internal(int pid, MapEntry *out, int max_entries) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return -errno;

    char line[1024];
    int count = 0;
    while (count < max_entries && fgets(line, sizeof(line), f)) {
        unsigned long lo = 0, hi = 0, off = 0;
        char perm[8] = {0};
        int pos = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %n", &lo, &hi, perm, &off, &pos) < 4) {
            continue;
        }
        out[count].lo = (uint64_t)lo;
        out[count].hi = (uint64_t)hi;
        strncpy(out[count].perm, perm, sizeof(out[count].perm) - 1);
        out[count].perm[sizeof(out[count].perm) - 1] = '\0';
        out[count].offset = (uint64_t)off;
        out[count].path[0] = '\0';
        if (pos > 0 && line[pos]) {
            char *p = line + pos;
            while (*p == ' ' || *p == '\t') p++;
            size_t len = strlen(p);
            while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r')) {
                p[--len] = '\0';
            }
            strncpy(out[count].path, p, sizeof(out[count].path) - 1);
            out[count].path[sizeof(out[count].path) - 1] = '\0';
        }
        count++;
    }
    fclose(f);
    return count;
}

static int ptrace_hold(int pid, int *used_seize) {
    *used_seize = 0;
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == 0) {
        *used_seize = 1;
        if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == 0) {
            int st = 0;
            waitpid(pid, &st, __WALL);
        }
        return 0;
    }
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
        int st = 0;
        waitpid(pid, &st, 0);
        return 0;
    }
    return -errno;
}

static void ptrace_release(int pid) {
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static ssize_t safe_pwrite_mem(int pid, int fd, const void *buf, size_t len, uint64_t addr) {
    ssize_t w = pwrite64(fd, buf, len, (off_t)addr);
    if (w == (ssize_t)len) return w;

    int used_seize = 0;
    if (ptrace_hold(pid, &used_seize) == 0) {
        int fd2 = fd;
        char mpath[64];
        if (fd2 < 0) {
            snprintf(mpath, sizeof(mpath), "/proc/%d/mem", pid);
            fd2 = open(mpath, O_RDWR);
        }
        if (fd2 >= 0) {
            w = pwrite64(fd2, buf, len, (off_t)addr);
            if (fd < 0) close(fd2);
        }
        ptrace_release(pid);
    }
    return w;
}

JNIEXPORT jint JNICALL
Java_io_bridger_BridgerNative_findPidByName(JNIEnv *env, jclass cls, jstring jpkg) {
    (void)cls;
    if (!jpkg) return 0;
    const char *pkg = (*env)->GetStringUTFChars(env, jpkg, NULL);
    if (!pkg) return 0;

    DIR *d = opendir("/proc");
    if (!d) {
        (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
        return 0;
    }

    int my_pid = (int)getpid();
    int found_pid = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        int pid = atoi(de->d_name);
        if (pid <= 0 || pid == my_pid) continue;

        char cmdpath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", pid);
        int fd = open(cmdpath, O_RDONLY);
        if (fd < 0) continue;
        char cmd[256] = {0};
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n <= 0) continue;
        cmd[n] = '\0';

        if (strcmp(cmd, pkg) == 0) {
            found_pid = pid;
            break;
        }
    }
    closedir(d);
    (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
    return found_pid;
}

JNIEXPORT jstring JNICALL
Java_io_bridger_BridgerNative_readMapsJson(JNIEnv *env, jclass cls, jint pid, jstring jfilterPerm, jstring jfilterPath, jlong filterSize) {
    (void)cls;
    const int MAX_SEGS = 8192;
    MapEntry *segs = (MapEntry *)calloc((size_t)MAX_SEGS, sizeof(MapEntry));
    if (!segs) return (*env)->NewStringUTF(env, "[]");

    int n = parse_maps_internal((int)pid, segs, MAX_SEGS);
    if (n <= 0) {
        free(segs);
        return (*env)->NewStringUTF(env, "[]");
    }

    const char *fperm = jfilterPerm ? (*env)->GetStringUTFChars(env, jfilterPerm, NULL) : NULL;
    const char *fpath = jfilterPath ? (*env)->GetStringUTFChars(env, jfilterPath, NULL) : NULL;

    size_t cap = 65536;
    char *out = (char *)malloc(cap);
    if (!out) {
        if (fperm) (*env)->ReleaseStringUTFChars(env, jfilterPerm, fperm);
        if (fpath) (*env)->ReleaseStringUTFChars(env, jfilterPath, fpath);
        free(segs);
        return (*env)->NewStringUTF(env, "[]");
    }

    size_t len = 0;
    out[len++] = '[';
    int emitted = 0;

    for (int i = 0; i < n; i++) {
        uint64_t sz = segs[i].hi - segs[i].lo;
        if (fperm && fperm[0] && strstr(segs[i].perm, fperm) == NULL) continue;
        if (fpath && fpath[0] && strstr(segs[i].path, fpath) == NULL) continue;
        if (filterSize > 0 && sz != (uint64_t)filterSize) continue;

        if (len + 512 >= cap) {
            cap *= 2;
            char *nb = (char *)realloc(out, cap);
            if (!nb) break;
            out = nb;
        }

        char clean_path[256];
        size_t o = 0;
        for (size_t k = 0; segs[i].path[k] && o + 2 < sizeof(clean_path); k++) {
            char c = segs[i].path[k];
            if (c == '"' || c == '\\') clean_path[o++] = '_';
            else if ((unsigned char)c >= 32 && (unsigned char)c < 127) clean_path[o++] = c;
        }
        clean_path[o] = '\0';

        int w = snprintf(
            out + len,
            cap - len,
            "%s{\"lo\":\"%" PRIx64 "\",\"hi\":\"%" PRIx64 "\",\"size\":%" PRIu64 ",\"perm\":\"%s\",\"offset\":\"%" PRIx64 "\",\"path\":\"%s\"}",
            emitted ? "," : "",
            segs[i].lo,
            segs[i].hi,
            sz,
            segs[i].perm,
            segs[i].offset,
            clean_path
        );
        if (w > 0) {
            len += (size_t)w;
            emitted++;
        }
    }

    out[len++] = ']';
    out[len] = '\0';

    if (fperm) (*env)->ReleaseStringUTFChars(env, jfilterPerm, fperm);
    if (fpath) (*env)->ReleaseStringUTFChars(env, jfilterPath, fpath);
    free(segs);

    jstring res = (*env)->NewStringUTF(env, out);
    free(out);
    return res;
}

JNIEXPORT jbyteArray JNICALL
Java_io_bridger_BridgerNative_readProcessMemory(JNIEnv *env, jclass cls, jint pid, jlong addr, jint length) {
    (void)cls;
    if (length <= 0 || length > (64 << 20)) return NULL;

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)pid);
    int fd = open(mpath, O_RDONLY);
    if (fd < 0) return NULL;

    uint8_t *buf = (uint8_t *)malloc((size_t)length);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ssize_t got = pread64(fd, buf, (size_t)length, (off_t)(uint64_t)addr);
    close(fd);
    if (got <= 0) {
        free(buf);
        return NULL;
    }

    jbyteArray arr = (*env)->NewByteArray(env, (jsize)got);
    if (arr) {
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)got, (const jbyte *)buf);
    }
    free(buf);
    return arr;
}

JNIEXPORT jint JNICALL
Java_io_bridger_BridgerNative_writeProcessMemory(JNIEnv *env, jclass cls, jint pid, jlong addr, jbyteArray jdata) {
    (void)cls;
    if (!jdata) return -1;
    jsize len = (*env)->GetArrayLength(env, jdata);
    if (len <= 0) return 0;

    jbyte *bytes = (*env)->GetByteArrayElements(env, jdata, NULL);
    if (!bytes) return -2;

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)pid);
    int fd = open(mpath, O_RDWR);
    ssize_t written = safe_pwrite_mem((int)pid, fd, bytes, (size_t)len, (uint64_t)addr);
    if (fd >= 0) close(fd);

    (*env)->ReleaseByteArrayElements(env, jdata, bytes, JNI_ABORT);
    return (jint)written;
}

JNIEXPORT jstring JNICALL
Java_io_bridger_BridgerNative_scanMemoryJson(JNIEnv *env, jclass cls, jint pid, jbyteArray jneedle, jboolean writableOnly, jint maxHits) {
    (void)cls;
    if (!jneedle) return (*env)->NewStringUTF(env, "[]");
    jsize nlen = (*env)->GetArrayLength(env, jneedle);
    if (nlen <= 0) return (*env)->NewStringUTF(env, "[]");
    if (maxHits <= 0) maxHits = 64;

    const int MAX_SEGS = 8192;
    MapEntry *segs = (MapEntry *)calloc((size_t)MAX_SEGS, sizeof(MapEntry));
    if (!segs) return (*env)->NewStringUTF(env, "[]");
    int nseg = parse_maps_internal((int)pid, segs, MAX_SEGS);
    if (nseg <= 0) {
        free(segs);
        return (*env)->NewStringUTF(env, "[]");
    }

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)pid);
    int fd = open(mpath, O_RDONLY);
    if (fd < 0) {
        free(segs);
        return (*env)->NewStringUTF(env, "[]");
    }

    uint8_t *needle = (uint8_t *)(*env)->GetByteArrayElements(env, jneedle, NULL);
    const size_t CHUNK = 4 << 20;
    uint8_t *buf = (uint8_t *)malloc(CHUNK + (size_t)nlen + 64);

    size_t cap = 32768;
    char *out = (char *)malloc(cap);
    size_t olen = 0;
    out[olen++] = '[';
    int hits = 0;

    for (int i = 0; i < nseg && hits < maxHits; i++) {
        if (segs[i].perm[0] != 'r') continue;
        if (writableOnly && segs[i].perm[1] != 'w') continue;
        if (strstr(segs[i].path, "[stack]") || strstr(segs[i].path, "/dev/")) continue;

        uint64_t slen = segs[i].hi - segs[i].lo;
        if (slen < (uint64_t)nlen || slen > (512ULL << 20)) continue;

        for (uint64_t off = 0; off < slen && hits < maxHits; off += CHUNK) {
            size_t want = (slen - off) > (CHUNK + (size_t)nlen) ? (CHUNK + (size_t)nlen) : (size_t)(slen - off);
            ssize_t got = pread64(fd, buf, want, (off_t)(segs[i].lo + off));
            if (got < nlen) break;

            size_t limit = (size_t)got - (size_t)nlen;
            for (size_t k = 0; k <= limit && hits < maxHits; k++) {
                if (buf[k] != needle[0]) continue;
                if (memcmp(buf + k, needle, (size_t)nlen) != 0) continue;

                uint64_t hit_addr = segs[i].lo + off + k;
                if (olen + 256 >= cap) {
                    cap *= 2;
                    char *nb = (char *)realloc(out, cap);
                    if (!nb) break;
                    out = nb;
                }
                int w = snprintf(
                    out + olen,
                    cap - olen,
                    "%s{\"addr\":\"%" PRIx64 "\",\"seg_lo\":\"%" PRIx64 "\",\"seg_size\":%" PRIu64 ",\"perm\":\"%s\"}",
                    hits ? "," : "",
                    hit_addr,
                    segs[i].lo,
                    slen,
                    segs[i].perm
                );
                if (w > 0) {
                    olen += (size_t)w;
                    hits++;
                }
                k += (size_t)nlen - 1;
            }
        }
    }

    out[olen++] = ']';
    out[olen] = '\0';

    free(buf);
    (*env)->ReleaseByteArrayElements(env, jneedle, (jbyte *)needle, JNI_ABORT);
    close(fd);
    free(segs);

    jstring res = (*env)->NewStringUTF(env, out);
    free(out);
    return res;
}

JNIEXPORT jint JNICALL
Java_io_bridger_BridgerNative_redirectStrings(JNIEnv *env, jclass cls, jint pid, jstring joldStr, jstring jnewStr, jboolean includeUtf16) {
    (void)cls;
    if (!joldStr || !jnewStr) return -1;
    const char *old_s = (*env)->GetStringUTFChars(env, joldStr, NULL);
    const char *new_s = (*env)->GetStringUTFChars(env, jnewStr, NULL);
    if (!old_s || !new_s) {
        if (old_s) (*env)->ReleaseStringUTFChars(env, joldStr, old_s);
        if (new_s) (*env)->ReleaseStringUTFChars(env, jnewStr, new_s);
        return -1;
    }

    size_t slen = strlen(old_s);
    size_t nlen = strlen(new_s);
    if (slen == 0 || nlen > slen) {
        (*env)->ReleaseStringUTFChars(env, joldStr, old_s);
        (*env)->ReleaseStringUTFChars(env, jnewStr, new_s);
        return -2;
    }

    /* Pad new_s with '/' if shorter than old_s so in-place URL replacement is exact length */
    uint8_t *a_old = (uint8_t *)malloc(slen);
    uint8_t *a_new = (uint8_t *)malloc(slen);
    uint8_t *u_old = (uint8_t *)malloc(slen * 2);
    uint8_t *u_new = (uint8_t *)malloc(slen * 2);
    for (size_t i = 0; i < slen; i++) {
        uint8_t co = (uint8_t)old_s[i];
        uint8_t cn = (i < nlen) ? (uint8_t)new_s[i] : (uint8_t)'/';
        a_old[i] = co;
        a_new[i] = cn;
        u_old[2 * i] = co;
        u_old[2 * i + 1] = 0;
        u_new[2 * i] = cn;
        u_new[2 * i + 1] = 0;
    }

    const int MAX_SEGS = 8192;
    MapEntry *segs = (MapEntry *)calloc((size_t)MAX_SEGS, sizeof(MapEntry));
    int nseg = segs ? parse_maps_internal((int)pid, segs, MAX_SEGS) : 0;

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)pid);
    int fd = open(mpath, O_RDWR);
    int rfd = (fd >= 0) ? fd : open(mpath, O_RDONLY);

    int patched = 0;
    const size_t CHUNK = 4 << 20;
    uint8_t *buf = (uint8_t *)malloc(CHUNK + slen * 2 + 64);

    if (rfd >= 0 && buf && nseg > 0) {
        for (int i = 0; i < nseg; i++) {
            int is_meta = strstr(segs[i].path, "global-metadata.dat") != NULL;
            if (segs[i].perm[0] != 'r') continue;
            if (segs[i].perm[1] != 'w' && !is_meta) continue;

            uint64_t seg_len = segs[i].hi - segs[i].lo;
            if (seg_len < slen || seg_len > (512ULL << 20)) continue;

            for (uint64_t off = 0; off < seg_len; off += CHUNK) {
                size_t want = (seg_len - off) > (CHUNK + slen * 2) ? (CHUNK + slen * 2) : (size_t)(seg_len - off);
                ssize_t got = pread64(rfd, buf, want, (off_t)(segs[i].lo + off));
                if (got < (ssize_t)slen) break;

                /* ASCII pass */
                for (size_t k = 0; k + slen <= (size_t)got; k++) {
                    if (buf[k] != a_old[0]) continue;
                    if (memcmp(buf + k, a_old, slen) != 0) continue;
                    uint64_t at = segs[i].lo + off + k;
                    if (safe_pwrite_mem((int)pid, fd, a_new, slen, at) == (ssize_t)slen) {
                        patched++;
                    }
                    k += slen - 1;
                }

                /* UTF-16LE pass */
                if (includeUtf16 && (size_t)got >= slen * 2) {
                    size_t ulen = slen * 2;
                    for (size_t k = 0; k + ulen <= (size_t)got; k++) {
                        if (buf[k] != u_old[0] || buf[k + 1] != 0) continue;
                        if (memcmp(buf + k, u_old, ulen) != 0) continue;
                        uint64_t at = segs[i].lo + off + k;
                        if (safe_pwrite_mem((int)pid, fd, u_new, ulen, at) == (ssize_t)ulen) {
                            patched++;
                        }
                        k += ulen - 1;
                    }
                }
            }
        }
    }

    if (buf) free(buf);
    if (rfd >= 0 && rfd != fd) close(rfd);
    if (fd >= 0) close(fd);
    if (segs) free(segs);
    free(a_old);
    free(a_new);
    free(u_old);
    free(u_new);
    (*env)->ReleaseStringUTFChars(env, joldStr, old_s);
    (*env)->ReleaseStringUTFChars(env, jnewStr, new_s);
    return patched;
}
