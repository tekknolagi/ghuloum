#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t Object;

extern Object scheme_entry(void);

#define fixnum_mask 3
#define fixnum_tag 0
#define fixnum_shift 2

bool is_fixnum(Object obj) {
  return (obj & fixnum_mask) == fixnum_tag;
}

int64_t unbox_fixnum(Object obj) {
  assert(is_fixnum(obj));
  return ((int64_t)obj) >> fixnum_shift;
}

void print_obj(Object obj) {
  FILE *fp = stdout;
  if (is_fixnum(obj)) {
    fprintf(fp, "%ld", unbox_fixnum(obj));
  } else {
    fprintf(fp, "<unknown %p>", (void*)obj);
  }
}

void println_obj(Object obj) {
  FILE *fp = stdout;
  print_obj(obj);
  fprintf(fp, "\n");
}

int main() {
  Object obj = scheme_entry();
  println_obj(obj);
}
