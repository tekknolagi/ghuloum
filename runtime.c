#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t Object;

extern Object scheme_entry(void);

#define fixnum_mask 3
#define fixnum_tag 0
#define fixnum_shift 2
#define char_tag 0xf
#define char_shift 8
#define obj_false 0x1f
#define obj_true 0x9f
#define empty_list 0x2f

bool is_fixnum(Object obj) {
  return (obj & fixnum_mask) == fixnum_tag;
}

int64_t unbox_fixnum(Object obj) {
  assert(is_fixnum(obj));
  return ((int64_t)obj) >> fixnum_shift;
}

bool is_char(Object obj) {
  return (obj & 0xff) == char_tag;
}

char unbox_char(Object obj) {
  assert(is_char(obj));
  return obj >> char_shift;
}

bool is_empty_list(Object obj) {
  return obj == empty_list;
}

void print_obj(Object obj) {
  FILE *fp = stdout;
  if (is_fixnum(obj)) {
    fprintf(fp, "%ld", unbox_fixnum(obj));
  } else if (is_char(obj)) {
    fprintf(fp, "'%c'", unbox_char(obj));
  } else if (obj == obj_true) {
    fprintf(fp, "#t");
  } else if (obj == obj_false) {
    fprintf(fp, "#f");
  } else if (is_empty_list(obj)) {
    fprintf(fp, "()");
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
