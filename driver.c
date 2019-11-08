#include <stdint.h>
#include <stdio.h>

uint32_t scheme_entry();

const unsigned kFixnumMask = 3;
const unsigned kFixnumTag = 0;
const unsigned kFixnumShift = 2;

const unsigned kCharMask = 0xff;
const unsigned kCharTag = 0x0f;
const unsigned kCharShift = 8;

const unsigned kBoolMask = 0x7f;
const unsigned kBoolTag = 0x1f;
const unsigned kBoolShift = 7;

const unsigned kNilMask = 0xff;
const unsigned kNilTag = 0x2f;

int main(int argc, char **argv) {
    uint32_t val = scheme_entry();
    if ((val & kFixnumMask) == kFixnumTag) {
        printf("int: %d\n", val >> kFixnumShift);
    } else if ((val & kCharMask) == kCharTag) {
        printf("char: %c\n", val >> kCharShift);
    } else if ((val & kBoolMask) == kBoolTag) {
        printf("bool: %s\n", (val >> kBoolShift) ? "true" : "false");
    } else if ((val & kNilMask) == kNilTag) {
        printf("list: ()\n");
    } else {
        printf("error\n");
    }
    return 0;
}
