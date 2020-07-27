#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#undef _GNU_SOURCE

#include "libtap/tap.h"

// Machine code

typedef unsigned char byte;

typedef enum {
  kWritable,
  kExecutable,
} BufferState;

typedef struct {
  byte *address;
  size_t len;
  BufferState state;
} Buffer;

void Buffer_init(Buffer *result, size_t len) {
  result->address = mmap(/*addr=*/NULL, len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         /*filedes=*/-1, /*off=*/0);
  assert(result->address != MAP_FAILED);
  result->len = len;
  result->state = kWritable;
}

void Buffer_deinit(Buffer *buf) {
  munmap(buf->address, buf->len);
  buf->address = NULL;
}

int Buffer_make_executable(Buffer *buf) {
  int result = mprotect(buf->address, buf->len, PROT_EXEC);
  buf->state = kExecutable;
  return result;
}

void Buffer_at_put(Buffer *buf, size_t pos, byte b) { buf->address[pos] = b; }

typedef struct {
  Buffer *buf;
  size_t pos;
} BufferWriter;

void BufferWriter_init(BufferWriter *writer, Buffer *buf) {
  writer->buf = buf;
  writer->pos = 0;
}

void Buffer_dump(BufferWriter *writer, FILE *fp) {
  for (size_t i = 0; i < writer->pos; i++) {
    fprintf(fp, "%.2x ", writer->buf->address[i]);
  }
  fprintf(fp, "\n");
}

void Buffer_write8(BufferWriter *writer, byte b) {
  assert(writer->pos < writer->buf->len);
  Buffer_at_put(writer->buf, writer->pos++, b);
}

void Buffer_write_arr(BufferWriter *writer, byte *arr, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Buffer_write8(writer, arr[i]);
  }
}

const int kBitsPerByte = 8; // bits
const int kWordSize = 8;    // bytes

void Buffer_write32(BufferWriter *writer, int32_t value) {
  for (size_t i = 0; i < 4; i++) {
    Buffer_write8(writer, (value >> (i * kBitsPerByte)) & 0xff);
  }
}

typedef enum {
  kRax = 0,
  kRcx,
  kRdx,
  kRbx,
  kRsp,
  kRbp,
  kRsi,
  kRdi,
} Register;

typedef enum {
  kAl = 0,
} SubRegister;

typedef enum {
  kEqual,
} Condition;

void Buffer_inc_reg(BufferWriter *writer, Register reg) {
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0xff);
  Buffer_write8(writer, 0xc0 + reg);
}

void Buffer_dec_reg(BufferWriter *writer, Register reg) {
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0xff);
  Buffer_write8(writer, 0xc8 + reg);
}

void Buffer_mov_reg_imm32(BufferWriter *writer, Register dst, int32_t src) {
  Buffer_write8(writer, 0xb8 + dst);
  Buffer_write32(writer, src);
}

void Buffer_add_reg_imm32(BufferWriter *writer, Register dst, int32_t src) {
  if (dst == kRax) {
    // Optimization: add eax, {imm32} can either be encoded as 05 {imm32} or 81
    // c0 {imm32}.
    Buffer_write8(writer, 0x05);
  } else {
    Buffer_write8(writer, 0x81);
    Buffer_write8(writer, 0xc0 + dst);
  }
  Buffer_write32(writer, src);
}

void Buffer_add_reg_stack(BufferWriter *writer, Register dst, int8_t offset) {
  assert(offset < 0 && "positive stack offset unimplemented");
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0x03);
  Buffer_write8(writer, 0x04 + (dst * 8) + (offset == 0 ? 0 : 0x40));
  Buffer_write8(writer, 0x24);
  Buffer_write8(writer, 0x100 + offset);
}

void Buffer_sub_reg_imm32(BufferWriter *writer, Register dst, int32_t src) {
  if (dst == kRax) {
    // Optimization: sub eax, {imm32} can either be encoded as 2d {imm32} or 81
    // e8 {imm32}.
    Buffer_write8(writer, 0x2d);
  } else {
    Buffer_write8(writer, 0x83);
    Buffer_write8(writer, 0xe8 + dst);
  }
  Buffer_write32(writer, src);
}

void Buffer_mov_reg_imm64(BufferWriter *writer, Register dst, int64_t src) {
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0xb8 + dst);
  for (size_t i = 0; i < 8; i++) {
    Buffer_write8(writer, (src >> (i * kBitsPerByte)) & 0xff);
  }
  Buffer_write8(writer, 0x00);
  Buffer_write8(writer, 0x00);
  Buffer_write8(writer, 0x00);
}

void Buffer_mov_reg_reg(BufferWriter *writer, Register dst, Register src) {
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0x89);
  Buffer_write8(writer, 0xc0 + dst + src * 8);
}

void Buffer_mov_reg_to_stack(BufferWriter *writer, Register src,
                             int8_t offset) {
  assert(offset < 0 && "positive stack offset unimplemented");
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0x89);
  Buffer_write8(writer, 0x04 + (src * 8) + (offset == 0 ? 0 : 0x40));
  Buffer_write8(writer, 0x24);
  Buffer_write8(writer, 0x100 + offset);
}

void Buffer_shl_reg(BufferWriter *writer, Register dst, int8_t bits) {
  assert(bits >= 0 && "too few bits");
  assert(bits < 64 && "too many bits");
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0xc1);
  Buffer_write8(writer, 0xe0 + dst);
  Buffer_write8(writer, bits);
}

void Buffer_and_reg_imm32(BufferWriter *writer, Register dst, int32_t value) {
  Buffer_write8(writer, 0x48);
  if (dst == kRax) {
    // Optimization: and eax, {imm32} can either be encoded as 48 25 {imm32} or
    // 48 81 e0 {imm32}.
    Buffer_write8(writer, 0x25);
    Buffer_write32(writer, value);
    return;
  }
  Buffer_write8(writer, 0x81);
  Buffer_write8(writer, 0xe0 + dst);
  Buffer_write32(writer, value);
}

void Buffer_or_reg_imm32(BufferWriter *writer, Register dst, int32_t value) {
  Buffer_write8(writer, 0x48);
  if (dst == kRax) {
    // Optimization: or eax, {imm32} can either be encoded as 48 0d {imm32} or
    // 48 81 c8 {imm32}.
    Buffer_write8(writer, 0x0d);
    Buffer_write32(writer, value);
    return;
  }
  Buffer_write8(writer, 0x81);
  Buffer_write8(writer, 0xc8 + dst);
  Buffer_write32(writer, value);
}

void Buffer_cmp_reg_imm32(BufferWriter *writer, Register dst, int32_t value) {
  if (dst == kRax) {
    // Optimization: cmp eax, {imm32} can either be encoded as 48 3d {imm32} or
    // 48 81 f8 {imm32}.
    Buffer_write8(writer, 0x48);
    Buffer_write8(writer, 0x3d);
    Buffer_write32(writer, value);
    return;
  }
  Buffer_write8(writer, 0x48);
  Buffer_write8(writer, 0x81);
  Buffer_write8(writer, 0xf8 + dst);
  Buffer_write32(writer, value);
}

void Buffer_setcc_reg(BufferWriter *writer, Condition cond, SubRegister dst) {
  assert(cond == kEqual && "other conditions unimplemented");
  Buffer_write8(writer, 0x0f);
  Buffer_write8(writer, 0x94);
  Buffer_write8(writer, 0xc0 + dst);
}

void Buffer_ret(BufferWriter *writer) { Buffer_write8(writer, 0xc3); }

// End Machine code

// AST

typedef enum {
  kFixnum,
  kAtom,
  kCons,
} ASTNodeType;

struct ASTNode;

typedef struct {
  struct ASTNode *car;
  struct ASTNode *cdr;
} ASTCons;

typedef struct ASTNode {
  ASTNodeType type;
  union {
    int fixnum;
    char *atom;
    ASTCons cons;
  } value;
} ASTNode;

ASTNode *AST_new_fixnum(int fixnum) {
  ASTNode *result = malloc(sizeof *result);
  result->type = kFixnum;
  result->value.fixnum = fixnum;
  return result;
}

ASTNode *AST_new_atom(char *atom) {
  ASTNode *result = malloc(sizeof *result);
  result->type = kAtom;
  result->value.atom = strdup(atom);
  return result;
}

ASTNode *AST_new_cons(ASTNode *car, ASTNode *cdr) {
  ASTNode *result = malloc(sizeof *result);
  result->type = kCons;
  result->value.cons.car = car;
  result->value.cons.cdr = cdr;
  return result;
}

int AST_is_atom(ASTNode *node) { return node->type == kAtom; }

int AST_atom_equals_cstr(ASTNode *node, char *cstr) {
  assert(AST_is_atom(node));
  return strcmp(node->value.atom, cstr) == 0;
}

ASTNode *AST_car(ASTNode *cons) {
  assert(cons->type == kCons);
  return cons->value.cons.car;
}
ASTNode *AST_cdr(ASTNode *cons) {
  assert(cons->type == kCons);
  return cons->value.cons.cdr;
}

static const int kFixnumMask = 0x3;
static const int kFixnumTag = 0x0;
static const int kFixnumShift = 2;

static const int kCharMask = 0xff;
static const int kCharTag = 0xf;
static const int kCharShift = 8;

static const int kBoolMask = 0xf;
static const int kBoolTag = 0x1f;
static const int kBoolShift = 7;

int AST_compile_expr(BufferWriter *writer, ASTNode *node, int stack_index);

ASTNode *operand1(ASTNode *args) { return AST_car(args); }
ASTNode *operand2(ASTNode *args) { return AST_car(AST_cdr(args)); }

int32_t encodeImmediateFixnum(int32_t f) {
  assert(f < 0x7fffffff && "too big");
  assert(f > -0x80000000L && "too small");
  return f << kFixnumShift;
}

int AST_compile_let(BufferWriter *writer, ASTNode *bindings, ASTNode *body,
                    int stack_index) {
  // TODO: if no bindings, emit body
  assert(AST_car(bindings) == NULL && "bindings not implemented");
  assert(AST_cdr(bindings) == NULL && "bindings not implemented");
  AST_compile_expr(writer, body, stack_index);
  return 0;
  // TODO: emit code for first binding expression
  // TODO: move result onto the stack
  // TODO: bind name (local, not global)
  // TODO: recursively compile let, other bindings
}

ASTNode *AST_let_bindings(ASTNode *args) { return AST_car(args); }

ASTNode *AST_let_body(ASTNode *args) { return AST_car(AST_cdr(args)); }

int AST_compile_call(BufferWriter *writer, ASTNode *fnexpr, ASTNode *args,
                     int stack_index) {
  if (AST_is_atom(fnexpr)) {
    // Assumed to be a primcall
    if (AST_atom_equals_cstr(fnexpr, "add1")) {
      AST_compile_expr(writer, operand1(args), stack_index);
      Buffer_add_reg_imm32(writer, kRax, encodeImmediateFixnum(1));
      return 0;
    }
    if (AST_atom_equals_cstr(fnexpr, "sub1")) {
      AST_compile_expr(writer, operand1(args), stack_index);
      Buffer_sub_reg_imm32(writer, kRax, encodeImmediateFixnum(1));
      return 0;
    }
    if (AST_atom_equals_cstr(fnexpr, "integer->char")) {
      AST_compile_expr(writer, operand1(args), stack_index);
      Buffer_shl_reg(writer, kRax, /*bits=*/kCharShift - kFixnumShift);
      // TODO: generate more compact code since we know we're only or-ing with a
      // byte
      Buffer_or_reg_imm32(writer, kRax, kCharTag);
      return 0;
    }
    if (AST_atom_equals_cstr(fnexpr, "zero?")) {
      AST_compile_expr(writer, operand1(args), stack_index);
      Buffer_cmp_reg_imm32(writer, kRax, 0);
      Buffer_mov_reg_imm32(writer, kRax, 0);
      Buffer_setcc_reg(writer, kEqual, kAl);
      Buffer_shl_reg(writer, kRax, kBoolShift);
      Buffer_or_reg_imm32(writer, kRax, kBoolTag);
      return 0;
    }
    if (AST_atom_equals_cstr(fnexpr, "+")) {
      AST_compile_expr(writer, operand2(args), stack_index);
      Buffer_mov_reg_to_stack(writer, kRax, /*offset=*/stack_index);
      AST_compile_expr(writer, operand1(args), stack_index - kWordSize);
      Buffer_add_reg_stack(writer, kRax, /*offset=*/stack_index);
      return 0;
    }
    if (AST_atom_equals_cstr(fnexpr, "let")) {
      return AST_compile_let(writer, AST_let_bindings(args), AST_let_body(args),
                             stack_index);
    }
    assert(0 && "unknown call");
  }
  assert(0 && "unknown call");
}

int AST_compile_expr(BufferWriter *writer, ASTNode *node, int stack_index) {
  switch (node->type) {
  case kFixnum: {
    uint32_t value = (uint32_t)node->value.fixnum;
    Buffer_mov_reg_imm32(writer, kRax, encodeImmediateFixnum(value));
    return 0;
  }
  case kCons: {
    // Assumed to be in the form (<expr> <op1> <op2> ...)
    return AST_compile_call(writer, AST_car(node), AST_cdr(node), stack_index);
  }
  case kAtom:
    // TODO: lookup variable in env
    // TODO: if unbound, raise
    // TODO: generate stack load
    assert(0 && "unimplemented");
  }
  return -1;
}

int AST_compile_function(BufferWriter *writer, ASTNode *node) {
  int result = AST_compile_expr(writer, node, -kWordSize);
  if (result != 0)
    return result;
  Buffer_ret(writer);
  return 0;
}

// End AST

// Testing

int call_intfunction(Buffer *buf) {
  assert(buf != NULL);
  assert(buf->address != NULL);
  assert(buf->state == kExecutable);
  int (*function)() = (int (*)())buf->address;
  return function();
}

void run_test(void (*test_body)(BufferWriter *)) {
  Buffer buf;
  Buffer_init(&buf, 100);
  {
    BufferWriter writer;
    BufferWriter_init(&writer, &buf);
    test_body(&writer);
  }
  Buffer_deinit(&buf);
}

#define EXPECT_EQUALS_BYTES(buf, arr)                                          \
  {                                                                            \
    int result =                                                               \
        cmp_ok(memcmp(buf->address, arr, sizeof arr), "==", 0, __func__);      \
    if (!result) {                                                             \
      printf("NOT EQUAL. Expected: ");                                         \
      for (size_t i = 0; i < sizeof arr; i++) {                                \
        printf("%.2x ", arr[i]);                                               \
      }                                                                        \
      printf("\n           Found:    ");                                       \
      for (size_t i = 0; i < sizeof arr; i++) {                                \
        printf("%.2x ", buf->address[i]);                                      \
      }                                                                        \
      printf("\n");                                                            \
    }                                                                          \
  }

#define EXPECT_CALL_EQUALS(buf, expected)                                      \
  cmp_ok(call_intfunction(buf), "==", expected, __func__)

#define TEST(name) static void test_##name(BufferWriter *writer)

TEST(write_bytes_manually) {
  byte arr[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
  Buffer_write_arr(writer, arr, sizeof arr);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, 42);
}

TEST(write_bytes_manually2) {
  byte arr[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xff, 0xc0, 0xc3};
  Buffer_write_arr(writer, arr, sizeof arr);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, 43);
}

TEST(mov_rax_imm32) {
  Buffer_mov_reg_imm32(writer, kRax, 42);
  byte expected[] = {0xb8, 0x2a, 0x00, 0x00, 0x00};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
}

TEST(mov_rcx_imm32) {
  Buffer_mov_reg_imm32(writer, kRcx, 42);
  byte expected[] = {0xb9, 0x2a, 0x00, 0x00, 0x00};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
}

TEST(mov_inc) {
  Buffer_mov_reg_imm32(writer, kRax, 42);
  Buffer_inc_reg(writer, kRax);
  Buffer_ret(writer);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, 43);
}

TEST(mov_rax_rax) {
  Buffer_mov_reg_reg(writer, /*dst=*/kRax, /*src=*/kRax);
  byte expected[] = {0x48, 0x89, 0xc0};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
}

TEST(mov_rax_rsi) {
  Buffer_mov_reg_reg(writer, /*dst=*/kRax, /*src=*/kRsi);
  byte expected[] = {0x48, 0x89, 0xf0};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
}

TEST(mov_rdi_rbp) {
  Buffer_mov_reg_reg(writer, /*dst=*/kRdi, /*src=*/kRbp);
  byte expected[] = {0x48, 0x89, 0xef};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
}

TEST(compile_fixnum) {
  // 123
  ASTNode *node = AST_new_fixnum(123);
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, 123; ret
  byte expected[] = {0xb8, 0xec, 0x01, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(123));
  free(node);
}

TEST(compile_primcall_add1) {
  // (add1 5)
  ASTNode *node =
      AST_new_cons(AST_new_atom("add1"), AST_new_cons(AST_new_fixnum(5), NULL));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, imm(5); add eax, imm(1); ret
  byte expected[] = {0xb8, 0x14, 0x00, 0x00, 0x00, 0x05,
                     0x04, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(6));
  // TODO: figure out how to collect ASTs
}

TEST(compile_primcall_sub1) {
  // (sub1 5)
  ASTNode *node =
      AST_new_cons(AST_new_atom("sub1"), AST_new_cons(AST_new_fixnum(5), NULL));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, imm(5); sub eax, imm(1); ret
  byte expected[] = {0xb8, 0x14, 0x00, 0x00, 0x00, 0x2d,
                     0x04, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(4));
  // TODO: figure out how to collect ASTs
}

TEST(compile_primcall_add1_sub1) {
  // (sub1 (add1 5))
  ASTNode *add1 =
      AST_new_cons(AST_new_atom("add1"), AST_new_cons(AST_new_fixnum(5), NULL));
  ASTNode *node = AST_new_cons(AST_new_atom("sub1"), AST_new_cons(add1, NULL));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, imm(5); add eax, imm(1); sub eax, imm(1); ret
  byte expected[] = {0xb8, 0x14, 0x00, 0x00, 0x00, 0x05, 0x04, 0x00,
                     0x00, 0x00, 0x2d, 0x04, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(5));
  // TODO: figure out how to collect ASTs
}

TEST(compile_primcall_sub1_add1) {
  // (add1 (sub1 5))
  ASTNode *sub1 =
      AST_new_cons(AST_new_atom("sub1"), AST_new_cons(AST_new_fixnum(5), NULL));
  ASTNode *node = AST_new_cons(AST_new_atom("add1"), AST_new_cons(sub1, NULL));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, imm(5); sub eax, imm(1); add eax, imm(1); ret
  byte expected[] = {0xb8, 0x14, 0x00, 0x00, 0x00, 0x2d, 0x04, 0x00,
                     0x00, 0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(5));
  // TODO: figure out how to collect ASTs
}

ASTNode *make_add(ASTNode *left, ASTNode *right) {
  return AST_new_cons(AST_new_atom("+"),
                      AST_new_cons(left, AST_new_cons(right, NULL)));
}

TEST(compile_add_two_ints) {
  // (+ 1 2)
  ASTNode *node = make_add(AST_new_fixnum(1), AST_new_fixnum(2));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // mov eax, imm(2); mov [rsp-8], rax; mov rax, imm(1); add rax, [rsp-8]
  byte expected[] = {0xb8, 0x08, 0x00, 0x00, 0x00, 0x48, 0x89,
                     0x44, 0x24, 0xf8, 0xb8, 0x04, 0x00, 0x00,
                     0x00, 0x48, 0x03, 0x44, 0x24, 0xf8, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(3));
  // TODO: figure out how to collect ASTs
}

TEST(compile_add_three_ints) {
  // (+ 1 (+ 2 3))
  ASTNode *node = make_add(AST_new_fixnum(1),
                           make_add(AST_new_fixnum(2), AST_new_fixnum(3)));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // 0:  b8 0c 00 00 00          mov    eax,0xc
  // 5:  48 89 44 24 f8          mov    QWORD PTR [rsp-0x8],rax
  // a:  b8 08 00 00 00          mov    eax,0x8
  // f:  48 03 44 24 f8          add    rax,QWORD PTR [rsp-0x8]
  // 14: 48 89 44 24 f8          mov    QWORD PTR [rsp-0x8],rax
  // 19: b8 04 00 00 00          mov    eax,0x4
  // 1e: 48 03 44 24 f8          add    rax,QWORD PTR [rsp-0x8]
  // 23: c3                      ret
  byte expected[] = {0xb8, 0x0c, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24,
                     0xf8, 0xb8, 0x08, 0x00, 0x00, 0x00, 0x48, 0x03, 0x44,
                     0x24, 0xf8, 0x48, 0x89, 0x44, 0x24, 0xf8, 0xb8, 0x04,
                     0x00, 0x00, 0x00, 0x48, 0x03, 0x44, 0x24, 0xf8, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(6));
  // TODO: figure out how to collect ASTs
}

TEST(compile_add_four_ints) {
  // (+ (+ 1 2) (+ 3 4))
  ASTNode *node = make_add(make_add(AST_new_fixnum(1), AST_new_fixnum(2)),
                           make_add(AST_new_fixnum(3), AST_new_fixnum(4)));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // 0:  b8 10 00 00 00          mov    eax,0x10
  // 5:  48 89 44 24 f8          mov    QWORD PTR [rsp-0x8],rax
  // a:  b8 0c 00 00 00          mov    eax,0xc
  // f:  48 03 44 24 f8          add    rax,QWORD PTR [rsp-0x8]
  // 14: 48 89 44 24 f8          mov    QWORD PTR [rsp-0x8],rax
  // 19: b8 08 00 00 00          mov    eax,0x8
  // 1e: 48 89 44 24 f0          mov    QWORD PTR [rsp-0x10],rax
  // 23: b8 04 00 00 00          mov    eax,0x4
  // 28: 48 03 44 24 f0          add    rax,QWORD PTR [rsp-0x10]
  // 2d: 48 03 44 24 f8          add    rax,QWORD PTR [rsp-0x8]
  // 32: c3                      ret
  byte expected[] = {0xb8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24,
                     0xf8, 0xb8, 0x0c, 0x00, 0x00, 0x00, 0x48, 0x03, 0x44,
                     0x24, 0xf8, 0x48, 0x89, 0x44, 0x24, 0xf8, 0xb8, 0x08,
                     0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0xf0, 0xb8,
                     0x04, 0x00, 0x00, 0x00, 0x48, 0x03, 0x44, 0x24, 0xf0,
                     0x48, 0x03, 0x44, 0x24, 0xf8, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(10));
  // TODO: figure out how to collect ASTs
}

int encodeImmediateChar(char c) {
  return (((unsigned int)c) << kCharShift) | kCharTag;
}

TEST(integer_to_char) {
  // (integer->char 65)
  ASTNode *node = AST_new_cons(AST_new_atom("integer->char"),
                               AST_new_cons(AST_new_fixnum(65), NULL));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // 0:  b8 04 01 00 00          mov    eax,0x104
  // 5:  48 c1 e0 06             shl    rax,0x6
  // 9:  48 25 0f 00 00 00       and    rax,0xf
  // f:  c3                      ret
  byte expected[] = {0xb8, 0x04, 0x01, 0x00, 0x00, 0x48, 0xc1, 0xe0,
                     0x06, 0x48, 0x0d, 0x0f, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateChar('A'));
  // TODO: figure out how to collect ASTs
}

ASTNode *call1(char *fnname, ASTNode *arg) {
  return AST_new_cons(AST_new_atom(fnname), AST_new_cons(arg, NULL));
}

int32_t encodeImmediateBool(bool value) {
  return ((value ? 1L : 0L) << kBoolShift) | kBoolTag;
}

TEST(zerop_with_zero_returns_true) {
  // (zero? (sub1 (add1 0)))
  ASTNode *node =
      call1("zero?", call1("sub1", call1("add1", AST_new_fixnum(0))));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // -> prelude
  // 0:  b8 00 00 00 00          mov    eax,0x0
  // 5:  05 04 00 00 00          add    eax,0x4
  // a:  2d 04 00 00 00          sub    eax,0x4
  // -> body of zero?
  // f:  48 3d 00 00 00 00       cmp    rax,0x0
  // 15: b8 00 00 00 00          mov    eax,0x0
  // 1a: 0f 94 c0                sete   al
  // 1d: 48 c1 e0 07             shl    rax,0x7
  // 21: 48 0d 1f 00 00 00       or     rax,0x1f
  // 27: c3                      ret
  byte expected[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0x05, 0x04, 0x00,
                     0x00, 0x00, 0x2d, 0x04, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00,
                     0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48, 0xc1, 0xe0,
                     0x07, 0x48, 0x0d, 0x1f, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateBool(true));
  // TODO: figure out how to collect ASTs
}

TEST(zerop_with_non_zero_returns_false) {
  // (zero? (sub1 (add1 0)))
  ASTNode *node =
      call1("zero?", call1("sub1", call1("add1", AST_new_fixnum(1))));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  // -> prelude
  // 0:  b8 00 00 00 00          mov    eax,0x0
  // 5:  05 04 00 00 00          add    eax,0x4
  // a:  2d 04 00 00 00          sub    eax,0x4
  // -> body of zero?
  // f:  48 3d 00 00 00 00       cmp    rax,0x0
  // 15: b8 00 00 00 00          mov    eax,0x0
  // 1a: 0f 94 c0                sete   al
  // 1d: 48 c1 e0 07             shl    rax,0x7
  // 21: 48 0d 1f 00 00 00       or     rax,0x1f
  // 27: c3                      ret
  byte expected[] = {0xb8, 0x04, 0x00, 0x00, 0x00, 0x05, 0x04, 0x00,
                     0x00, 0x00, 0x2d, 0x04, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00,
                     0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48, 0xc1, 0xe0,
                     0x07, 0x48, 0x0d, 0x1f, 0x00, 0x00, 0x00, 0xc3};
  EXPECT_EQUALS_BYTES(writer->buf, expected);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateBool(false));
  // TODO: figure out how to collect ASTs
}

TEST(let_with_no_bindings) {
  // (let () (+ 1 2))
  ASTNode *node = AST_new_cons(
      AST_new_atom("let"),
      AST_new_cons(
          /*bindings*/ AST_new_cons(NULL, NULL),
          AST_new_cons(/*body*/ make_add(AST_new_fixnum(1), AST_new_fixnum(2)),
                       NULL)));
  int result = AST_compile_function(writer, node);
  cmp_ok(result, "==", 0, __func__);
  Buffer_make_executable(writer->buf);
  EXPECT_CALL_EQUALS(writer->buf, encodeImmediateFixnum(3));
  // TODO: figure out how to collect ASTs
}

int run_tests() {
  plan(NO_PLAN);
  run_test(test_write_bytes_manually);
  run_test(test_write_bytes_manually2);
  run_test(test_mov_rax_imm32);
  run_test(test_mov_rcx_imm32);
  run_test(test_mov_inc);
  run_test(test_mov_rax_rax);
  run_test(test_mov_rax_rsi);
  run_test(test_mov_rdi_rbp);
  run_test(test_compile_fixnum);
  run_test(test_compile_primcall_add1);
  run_test(test_compile_primcall_sub1);
  run_test(test_compile_primcall_add1_sub1);
  run_test(test_compile_primcall_sub1_add1);
  run_test(test_compile_add_two_ints);
  run_test(test_compile_add_three_ints);
  run_test(test_compile_add_four_ints);
  run_test(test_integer_to_char);
  run_test(test_zerop_with_zero_returns_true);
  run_test(test_zerop_with_non_zero_returns_false);
  run_test(test_let_with_no_bindings);
  done_testing();
}

// End Testing

int main() { return run_tests(); }
