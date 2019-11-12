#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint64_t word;

word scheme_entry(void* heap);

int main(int argc, char **argv) {
    word *heap = malloc(3000);
    fprintf(stdout, "0x%lx\n", scheme_entry(heap));
    free(heap);
    return 0;
}
