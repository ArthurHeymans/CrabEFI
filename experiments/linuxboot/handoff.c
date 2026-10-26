/* QEMU q35-only experiment. Run as root inside the disposable guest, not host.
 * Serialize coreboot-compatible tables from Linux's firmware (not /proc/iomem's
 * kernel allocation) map. No Linux pointers or firmware Runtime Services survive.
 */
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/klog.h>
#include <unistd.h>

#define BASE 0x08000000ULL
#define END  0x08100000ULL
struct __attribute__((packed)) range { uint64_t base, size; uint32_t type; };
static struct range ranges[64];
static unsigned nr;
static unsigned char tables[16384];
static size_t used = 24;
static uint32_t records;

static void put(const void *data, size_t size) {
    if (used + size > sizeof tables) errx(1, "handoff too large");
    memcpy(tables + used, data, size);
    used += size;
}
static void record(uint32_t tag, const void *data, uint32_t size) {
    uint32_t header[] = { tag, size + 8 };
    put(header, sizeof header);
    put(data, size);
    records++;
}
static uint64_t read_number(const char *path) {
    FILE *f = fopen(path, "r");
    unsigned long long n;
    if (!f || fscanf(f, "%llx", &n) != 1) errx(1, "read %s", path);
    fclose(f);
    return n;
}
static void add_range(uint64_t start, uint64_t end, uint32_t type) {
    if (start >= end) return;
    if (nr == 64) errx(1, "too many memory regions");
    ranges[nr++] = (struct range) {start, end - start, type};
}
static int compare(const void *a, const void *b) {
    uint64_t x = ((const struct range *)a)->base, y = ((const struct range *)b)->base;
    return (x > y) - (x < y);
}
static void memory_map(void) {
    DIR *dir = opendir("/sys/firmware/memmap");
    struct dirent *entry;
    int arena_found = 0;
    if (!dir) err(1, "firmware memmap unavailable");
    while ((entry = readdir(dir))) {
        char path[512], type[80];
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "/sys/firmware/memmap/%s/start", entry->d_name);
        uint64_t start = read_number(path);
        snprintf(path, sizeof path, "/sys/firmware/memmap/%s/end", entry->d_name);
        uint64_t end = read_number(path) + 1;
        snprintf(path, sizeof path, "/sys/firmware/memmap/%s/type", entry->d_name);
        FILE *f = fopen(path, "r");
        if (!f || !fgets(type, sizeof type, f)) errx(1, "read memory type");
        fclose(f);
        type[strcspn(type, "\n")] = 0;
        uint32_t kind = !strcmp(type, "System RAM") ? 1 :
                        !strcmp(type, "ACPI Tables") ? 3 :
                        !strcmp(type, "ACPI Non-volatile Storage") ? 4 : 2;
        if (kind == 1) {
            start = (start + 4095) & ~4095ULL;
            end &= ~4095ULL;
        } else {
            start &= ~4095ULL;
            end = (end + 4095) & ~4095ULL;
        }
        if (kind == 1 && start <= BASE && end >= END) {
            add_range(start, BASE, kind);
            add_range(BASE, END, 2);
            add_range(END, end, kind);
            arena_found = 1;
        } else {
            add_range(start, end, kind);
        }
    }
    closedir(dir);
    if (!arena_found) errx(1, "wrapper arena is not wholly in firmware RAM");
    qsort(ranges, nr, sizeof ranges[0], compare);
    for (unsigned i = 1; i < nr; i++)
        if (ranges[i-1].base + ranges[i-1].size > ranges[i].base)
            errx(1, "overlapping firmware map");
    record(1, ranges, nr * sizeof ranges[0]);
}
static uint64_t rsdp(void) {
    char *log = calloc(1, 1024 * 1024);
    if (!log || klogctl(3, log, 1024 * 1024 - 1) < 0) err(1, "kernel log");
    char *p = strstr(log, "ACPI: RSDP 0x");
    if (!p) errx(1, "RSDP physical address missing from kernel log");
    uint64_t addr = strtoull(p + strlen("ACPI: RSDP "), NULL, 16);
    free(log);
    int reserved = 0;
    for (unsigned i = 0; i < nr; i++)
        if (ranges[i].type != 1 && addr >= ranges[i].base &&
            addr + 36 <= ranges[i].base + ranges[i].size) reserved = 1;
    if (!reserved) errx(1, "RSDP is not in preserved firmware memory");
    int fd = open("/dev/mem", O_RDONLY);
    unsigned char data[36];
    if (fd < 0 || pread(fd, data, sizeof data, addr) != sizeof data ||
        memcmp(data, "RSD PTR ", 8)) errx(1, "RSDP validation failed");
    close(fd);
    unsigned sum = 0;
    for (unsigned i = 0; i < 20; i++) sum += data[i];
    if (sum & 255) errx(1, "bad RSDP checksum");
    fprintf(stderr, "LINUXBOOT_RSDP=%#llx\n", (unsigned long long)addr);
    return addr;
}
static void qemu_framebuffer(void) {
    /* Deliberately restricted to QEMU's std-vga in slot 1. No native GPU driver. */
    const char *device = "/sys/bus/pci/devices/0000:00:01.0/";
    char path[160];
    snprintf(path, sizeof path, "%svendor", device);
    if (read_number(path) != 0x1234) errx(1, "not QEMU std-vga");
    snprintf(path, sizeof path, "%sdevice", device);
    if (read_number(path) != 0x1111) errx(1, "not QEMU std-vga");
    snprintf(path, sizeof path, "%sresource", device);
    FILE *f = fopen(path, "r");
    unsigned long long base, end, flags;
    if (!f || fscanf(f, "%llx %llx %llx", &base, &end, &flags) != 3 ||
        !base || end - base + 1 < 1024 * 768 * 4) errx(1, "bad VGA BAR");
    fclose(f);
    if (ioperm(0x1ce, 3, 1)) err(1, "VBE I/O permission");
    const uint16_t regs[][2] = {{4, 0}, {1, 1024}, {2, 768}, {3, 32},
                                {6, 1024}, {8, 0}, {9, 0}, {4, 0x41}};
    for (unsigned i = 0; i < sizeof regs / sizeof regs[0]; i++) {
        outw(regs[i][0], 0x1ce);
        outw(regs[i][1], 0x1cf);
    }
    struct __attribute__((packed)) {
        uint64_t address;
        uint32_t width, height, stride;
        uint8_t bpp, red_pos, red_size, green_pos, green_size;
        uint8_t blue_pos, blue_size, reserved_pos, reserved_size;
    } fb = {base, 1024, 768, 4096, 32, 16, 8, 8, 8, 0, 8, 24, 8};
    record(0x12, &fb, sizeof fb);
    fprintf(stderr, "LINUXBOOT_FRAMEBUFFER=%#llx\n", base);
}
static uint16_t checksum(const unsigned char *p, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i++) sum += (uint32_t)p[i] << ((i & 1) * 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--qemu-only"))
        errx(1, "usage (DISPOSABLE QEMU GUEST ONLY): handoff --qemu-only > handoff.bin");
    memory_map();
    uint64_t acpi = rsdp();
    record(0x43, &acpi, sizeof acpi);
    uint32_t serial[] = {1, 0x3f8, 115200, 1, 1843200};
    record(0xf, serial, sizeof serial);
    qemu_framebuffer();
    uint32_t header[] = {0x4f49424c, 24, 0, used - 24,
                         checksum(tables + 24, used - 24), records};
    memcpy(tables, header, sizeof header);
    header[2] = checksum(tables, 24);
    memcpy(tables, header, sizeof header);
    if (fwrite(tables, 1, used, stdout) != used || fflush(stdout)) err(1, "write handoff");
    fprintf(stderr, "LINUXBOOT_HANDOFF_READY regions=%u bytes=%zu\n", nr, used);
    return 0;
}
