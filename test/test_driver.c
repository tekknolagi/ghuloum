#include <stdint.h>
#include <stdio.h>

uint32_t scheme_entry(void* heap);

int main(int argc, char **argv) {
    fprintf(stdout, "0x%x\n", scheme_entry(NULL));
    return 0;
}
