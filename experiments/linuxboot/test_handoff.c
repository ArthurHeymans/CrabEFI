/* Run SMBIOS staging against in-memory fixtures, never host firmware or I/O. */
#define fopen fixture_fopen
#define main guest_main
#include "handoff.c"
#undef main
#undef fopen

static unsigned char fixture_entry[32];
static size_t fixture_size;
static unsigned char fixture_dmi[] = {127, 4, 0, 0, 0, 0};

FILE *fixture_fopen(const char *path, const char *mode) {
    (void)mode;
    if (!strcmp(path, "/sys/firmware/dmi/tables/smbios_entry_point"))
        return fmemopen(fixture_entry, fixture_size, "rb");
    if (!strcmp(path, "/sys/firmware/dmi/tables/DMI"))
        return fmemopen(fixture_dmi, sizeof fixture_dmi, "rb");
    errx(1, "unexpected fixture path: %s", path);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int version = atoi(argv[1]);
    if (version == 3) {
        fixture_size = 24;
        memcpy(fixture_entry, "_SM3_", 5);
        fixture_entry[6] = fixture_size;
        fixture_entry[7] = 3;
        fixture_entry[5] = -byte_sum(fixture_entry, fixture_size);
    } else {
        fixture_size = 31;
        memcpy(fixture_entry, "_SM_", 4);
        fixture_entry[5] = fixture_size;
        memcpy(fixture_entry + 16, "_DMI_", 5);
        fixture_entry[21] = -byte_sum(fixture_entry + 16, 15);
        fixture_entry[4] = -byte_sum(fixture_entry, fixture_size);
    }
    if (version == 0) fixture_entry[0] ^= 1; /* Must be rejected. */
    if (smbios() != 0x1100 + sizeof fixture_dmi) return 3;
    if (used != 48 || records != 1) return 4;
    unsigned char *entry = tables + 0x1000;
    if (byte_sum(entry, fixture_size)) return 5;
    uint64_t address = 0;
    if (version == 3) {
        memcpy(&address, entry + 16, 8);
        uint32_t size;
        memcpy(&size, entry + 12, 4);
        if (size != sizeof fixture_dmi) return 6;
    } else {
        if (byte_sum(entry + 16, 15)) return 7;
        memcpy(&address, entry + 24, 4);
        uint16_t size;
        memcpy(&size, entry + 22, 2);
        if (size != sizeof fixture_dmi) return 8;
    }
    if (address != BASE + 0x4000 + 0x1100) return 9;
    if (memcmp(tables + 0x1100, fixture_dmi, sizeof fixture_dmi)) return 10;
    return 0;
}
