#include "syscallrecorder.h"
#include "syscallrecorder.skel.h"

#include <argp.h>
#include <bpf/bpf.h>
#include <seccomp.h>
#include <signal.h>
#include <unistd.h>

#define printfe(...) fprintf(stderr, __VA_ARGS__)
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

const char * argp_program_version = "syscallrecorder 0.1.0";

static const char argp_program_doc[] =
    "syscallrecorder - A simple PID based syscall recorder\n"
    "\n"
    "USAGE: syscallrecorder [-h] [-v] [-o FILE] -p PID\n";

static const struct argp_option options[] = {
    {"verbose", 'v', NULL, 0, "Verbose output"},
    {"pid", 'p', "PID", 0, "PID to trace"},
    {"output", 'o', "FILE", 0, "Output the syscalls to a file"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the help"},
    {},
};

static struct env {
    bool verbose;
    pid_t pid;
    char * file;
} env = {
    .pid = -1,
};

static pid_t parse_pid(const char * arg, int * ret)
{
    char * end;

    errno = 0;
    long value = strtol(arg, &end, 10);

    if (errno) {
        printfe("Convert string to int: %s: %s\n", arg, strerror(errno));
        return -1;
    } else if (end == arg || value < 1 || value > INT_MAX) {
        return -1;
    }

    if (ret) {
        *ret = value;
    }

    return 0;
}

static error_t parse_arg(int key, char * arg, struct argp_state * state)
{
    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'p':
            int err = parse_pid(arg, &env.pid);
            if (err) {
                printfe("Invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 'o':
            env.file = arg;
            break;
        case ARGP_KEY_END:
            if (env.pid == -1) {
                printfe("No PID provided but required\n");
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char * format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop = 0;

void sigint(int)
{
    stop = 1;
}

void handle_event(void * ctx, int cpu, void * data, unsigned int data_sz)
{
    const struct event_t * event = data;
    printf("Got stop event\n");
    stop = event->stop;
}

void handle_lost_events(void * ctx, int cpu, unsigned long long lost_cnt)
{
    printfe("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static bool read_values(int fd, struct data_t * values, unsigned int * count)
{
    struct data_t orig_values[*count];
    void *in = NULL, *out;
    unsigned int i, n, n_read = 0, keys[*count];
    int err = 0;

    while (n_read < *count && !err) {
        n = *count - n_read;
        err = bpf_map_lookup_and_delete_batch(fd, &in, &out, keys + n_read,
                                              orig_values + n_read, &n, NULL);
        if (err && errno != ENOENT) {
            return false;
        }
        n_read += n;
        in = out;
    }

    for (i = 0; i < n_read; i++) {
        values[i].count = orig_values[i].count;
        values[i].count_failed = orig_values[i].count_failed;
        values[i].syscall_id = keys[i];
    }

    *count = n_read;
    return true;
}

static void print_header(void)
{
    printf("\n%-15s %10s %10s\n", "SYSCALL", "COUNT", "FAILED");
}

static void print(struct data_t * values, size_t count)
{
    print_header();

    FILE * file = NULL;
    if (env.file) {
        file = fopen(env.file, "w+");
    }

    for (int i = 0; i < count; i++) {
        char * syscall_name = seccomp_syscall_resolve_num_arch(
            SCMP_ARCH_NATIVE, values[i].syscall_id);
        if (syscall_name == NULL) {
            printf("%-15d %10llu %10llu\n", values[i].syscall_id,
                   values[i].count, values[i].count_failed);
        } else {
            if (env.file) {
                fprintf(file, "%s\n", syscall_name);
            }
            printf("%-15s %10llu %10llu\n", syscall_name, values[i].count,
                   values[i].count_failed);
            free(syscall_name);
        }
    }

    printf("\n");

    if (env.file) {
        fclose(file);
        printf("Wrote syscalls to file %s\n", env.file);
    }
}

int main(int argc, char * argv[])
{
    static const struct argp argp = {
        .options = options,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    libbpf_set_print(libbpf_print_fn);

    struct syscallrecorder_bpf * obj = syscallrecorder_bpf__open();
    if (!obj) {
        printfe("Failed to open BPF object\n");
        return 1;
    }
    obj->rodata->pid = env.pid;

    err = syscallrecorder_bpf__load(obj);
    if (err) {
        printfe("Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    obj->links.sys_exit = bpf_program__attach(obj->progs.sys_exit);
    err = libbpf_get_error(obj->links.sys_exit);
    if (err) {
        printfe("Failed to attach sys_exit program: %s\n", strerror(-err));
        goto cleanup;
    }

    obj->links.process_exit = bpf_program__attach(obj->progs.process_exit);
    err = libbpf_get_error(obj->links.process_exit);
    if (err) {
        printfe("Failed to attach process_exit program: %s\n", strerror(-err));
        goto cleanup;
    }

    struct perf_buffer_opts pb_opts = {.sample_cb = handle_event,
                                       .lost_cb = handle_lost_events};
    struct perf_buffer * pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
                                               PERF_BUFFER_PAGES, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        printfe("Failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    if (signal(SIGINT, sigint) == SIG_ERR) {
        printfe("Can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("Tracing syscalls…\n");
    while (!stop) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && errno != EINTR) {
            printfe("Error polling perf buffer: %s\n", strerror(errno));
            goto cleanup;
        }
        err = 0;
    }

    unsigned int count = MAX_ENTRIES;
    struct data_t values[MAX_ENTRIES];
    if (!read_values(bpf_map__fd(obj->maps.data), values, &count)) {
        printfe("Can't read values: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }
    if (!count) {
        printfe("\nNo syscalls recorded\n");
        goto cleanup;
    }

    print(values, count);

cleanup:
    syscallrecorder_bpf__destroy(obj);
    return err != 0;
}
