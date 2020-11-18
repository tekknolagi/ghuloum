// vim: set tabstop=2 shiftwidth=2 textwidth=79 expandtab:
// gcc -O2 -g -Wall -Wextra -pedantic -fno-strict-aliasing
//   assets/code/lisp/compiling-closures.c

// In general: https://course.ccs.neu.edu/cs4410sp20/#%28part._lectures%29
// https://course.ccs.neu.edu/cs4410sp20/lec_let-and-stack_notes.html#%28part._let._.Growing_the_language__adding_let%29

// _GNU_SOURCE is used for MAP_ANONYMOUS in sys/mman.h and strdup in string.h
#define _GNU_SOURCE
#include <assert.h> // for assert
#include <stdarg.h>
#include <stdbool.h>  // for bool
#include <stddef.h>   // for NULL
#include <stdint.h>   // for int32_t, etc
#include <stdio.h>    // for getline, fprintf
#include <string.h>   // for memcpy
#include <sys/mman.h> // for mmap
#undef _GNU_SOURCE

#include "greatest.h"

#define WARN_UNUSED __attribute__((warn_unused_result))

// Objects

typedef intptr_t word;
typedef uintptr_t uword;

// These constants are defined in a enum because the right hand side of a
// statement like
//     static const int kFoo = ...;
// must be a so-called "Integer Constant Expression". Compilers are required to
// support a certain set of these expressions, but are not required to support
// arbitrary arithmetic with other integer constants. Compilers such as gcc
// before gcc-8 just decided not to play this game, while gcc-8+ and Clang play
// just fine.
// Since this arithmetic with constant values works just fine for enums, make
// all these constants enum values instead.
// See https://twitter.com/tekknolagi/status/1328449329472835586 for more info.
enum {
  kBitsPerByte = 8,                        // bits
  kWordSize = sizeof(word),                // bytes
  kBitsPerWord = kWordSize * kBitsPerByte, // bits

  kIntegerTag = 0x0,     // 0b00
  kIntegerTagMask = 0x3, // 0b11
  kIntegerShift = 2,
  kIntegerBits = kBitsPerWord - kIntegerShift,

  kImmediateTagMask = 0x3f,

  kCharTag = 0x0f,  // 0b00001111
  kCharMask = 0xff, // 0b11111111
  kCharShift = 8,

  kBoolTag = 0x1f,  // 0b0011111
  kBoolMask = 0x80, // 0b10000000
  kBoolShift = 7,

  kNilTag = 0x2f, // 0b101111

  kErrorTag = 0x3f, // 0b111111

  kPairTag = 0x1,               // 0b001
  kSymbolTag = 0x5,             // 0b101
  kClosureTag = 0x6,            // 0b110
  kHeapTagMask = ((uword)0x7),  // 0b000...111
  kHeapPtrMask = ~kHeapTagMask, // 0b1111...1000

  kCarIndex = 0,
  kCarOffset = kCarIndex * kWordSize,
  kCdrIndex = kCarIndex + 1,
  kCdrOffset = kCdrIndex * kWordSize,
  kPairSize = kCdrOffset + kWordSize,

  kClosureLabelIndex = 0,
  kClosureLabelOffset = kClosureLabelIndex * kWordSize,
};

// These are defined as macros because they will not work as static const int
// constants (per above explanation), and enum constants are only required to
// be an int wide (per ISO C).
#define INTEGER_MAX ((1LL << (kIntegerBits - 1)) - 1)
#define INTEGER_MIN (-(1LL << (kIntegerBits - 1)))

uword Object_encode_integer(word value) {
  assert(value < INTEGER_MAX && "too big");
  assert(value > INTEGER_MIN && "too small");
  return value << kIntegerShift;
}

word Object_decode_integer(uword value) { return (word)value >> kIntegerShift; }

bool Object_is_integer(uword value) {
  return (value & kIntegerTagMask) == kIntegerTag;
}

uword Object_encode_char(char value) {
  return ((uword)value << kCharShift) | kCharTag;
}

char Object_decode_char(uword value) {
  return (value >> kCharShift) & kCharMask;
}

bool Object_is_char(uword value) {
  return (value & kImmediateTagMask) == kCharTag;
}

uword Object_encode_bool(bool value) {
  return ((uword)value << kBoolShift) | kBoolTag;
}

bool Object_decode_bool(uword value) { return value & kBoolMask; }

uword Object_true() { return Object_encode_bool(true); }

uword Object_false() { return Object_encode_bool(false); }

uword Object_nil() { return kNilTag; }

uword Object_error() { return kErrorTag; }

uword Object_address(const void *obj) { return (uword)obj & kHeapPtrMask; }

bool Object_is_pair(uword value) { return (value & kHeapTagMask) == kPairTag; }

uword Object_pair_car(uword value) {
  assert(Object_is_pair(value));
  return ((uword *)Object_address((void *)value))[kCarIndex];
}

uword Object_pair_cdr(uword value) {
  assert(Object_is_pair(value));
  return ((uword *)Object_address((void *)value))[kCdrIndex];
}

bool Object_is_closure(uword value) {
  return (value & kHeapTagMask) == kClosureTag;
}

uword Object_closure_label(uword value) {
  assert(Object_is_closure(value));
  return ((uword *)Object_address((void *)value))[kClosureLabelIndex];
}

uword Object_closure_freevar(uword value, word n) {
  assert(Object_is_closure(value));
  // +1 for label
  return ((uword *)Object_address((void *)value))[n + 1];
}

// End Objects

// Buffer

typedef unsigned char byte;

typedef enum {
  kWritable,
  kExecutable,
} BufferState;

typedef struct {
  byte *address;
  BufferState state;
  word len;
  word capacity;
  word entrypoint;
} Buffer;

byte *Buffer_alloc_writable(word capacity) {
  byte *result = mmap(/*addr=*/NULL, capacity, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE,
                      /*filedes=*/-1, /*off=*/0);
  assert(result != MAP_FAILED);
  return result;
}

void Buffer_init(Buffer *result, word capacity) {
  result->address = Buffer_alloc_writable(capacity);
  assert(result->address != MAP_FAILED);
  result->state = kWritable;
  result->len = 0;
  result->capacity = capacity;
  result->entrypoint = 0;
}

word Buffer_len(Buffer *buf) { return buf->len; }

void Buffer_deinit(Buffer *buf) {
  munmap(buf->address, buf->capacity);
  buf->address = NULL;
  buf->len = 0;
  buf->capacity = 0;
  buf->entrypoint = 0;
}

int Buffer_make_executable(Buffer *buf) {
  int result = mprotect(buf->address, buf->len, PROT_EXEC);
  buf->state = kExecutable;
  return result;
}

byte Buffer_at8(Buffer *buf, word pos) { return buf->address[pos]; }

void Buffer_at_put8(Buffer *buf, word pos, byte b) { buf->address[pos] = b; }

word max(word left, word right) { return left > right ? left : right; }

void Buffer_ensure_capacity(Buffer *buf, word additional_capacity) {
  if (buf->len + additional_capacity <= buf->capacity) {
    return;
  }
  word new_capacity =
      max(buf->capacity * 2, buf->capacity + additional_capacity);
  byte *address = Buffer_alloc_writable(new_capacity);
  memcpy(address, buf->address, buf->len);
  int result = munmap(buf->address, buf->capacity);
  assert(result == 0 && "munmap failed");
  buf->address = address;
  buf->capacity = new_capacity;
}

void Buffer_write8(Buffer *buf, byte b) {
  Buffer_ensure_capacity(buf, sizeof b);
  Buffer_at_put8(buf, buf->len++, b);
}

void Buffer_write32(Buffer *buf, int32_t value) {
  for (uword i = 0; i < sizeof(value); i++) {
    Buffer_write8(buf, (value >> (i * kBitsPerByte)) & 0xff);
  }
}

void Buffer_at_put32(Buffer *buf, word offset, int32_t value) {
  for (uword i = 0; i < sizeof(value); i++) {
    Buffer_at_put8(buf, offset + i, (value >> (i * kBitsPerByte)) & 0xff);
  }
}

void Buffer_write_arr(Buffer *buf, const byte *arr, word arr_size) {
  Buffer_ensure_capacity(buf, arr_size);
  for (word i = 0; i < arr_size; i++) {
    Buffer_write8(buf, arr[i]);
  }
}

void Buffer_dump(Buffer *buf, FILE *fp) {
  for (word i = 0; i < Buffer_len(buf); i++) {
    fprintf(fp, "%.2x ", buf->address[i]);
  }
  fprintf(fp, "\n");
}

// End Buffer

// Emit

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
  kCl,
  kDl,
  kBl,
  kAh,
  kCh,
  kDh,
  kBh,
} PartialRegister;

typedef enum {
  kOverflow = 0,
  kNotOverflow,
  kBelow,
  kCarry = kBelow,
  kNotAboveOrEqual = kBelow,
  kAboveOrEqual,
  kNotBelow = kAboveOrEqual,
  kNotCarry = kAboveOrEqual,
  kEqual,
  kZero = kEqual,
  kLess = 0xc,
  kNotGreaterOrEqual = kLess,
  // TODO(max): Add more
} Condition;

typedef enum {
  kModDeref = 0,
  kModDisp8,
  kModDisp32,
  kModDirect,
} Mod;

typedef enum {
  kNear = 2,
  kFar = 3,
} CallDistance;

typedef struct Indirect {
  Register reg;
  word disp;
} Indirect;

Indirect Ind(Register reg, word disp) {
  return (Indirect){.reg = reg, .disp = disp};
}

// [ Instruction Prefixes (1 byte, optional) ]
// [ Opcode (1, 2, or 3 bytes) ]
// [ ModR/M (1 byte, if required) ]
// [ Scale-Index-Base (1 byte, if required) ]
// [ Displacement (1, 2, or 4 bytes, if required) ]
// [ Immediate data (1, 2, or 4 bytes, if required) ]

// http://www.c-jump.com/CIS77/CPU/x86/lecture.html
// https://wiki.osdev.org/X86-64_Instruction_Encoding

const byte kRexPrefix = 0x48;

typedef enum {
  Scale1 = 0,
  Scale2,
  Scale4,
  Scale8,
} Scale;

typedef enum {
  kIndexRax = 0,
  kIndexRcx,
  kIndexRdx,
  kIndexRbx,
  kIndexNone,
  kIndexRbp,
  kIndexRsi,
  kIndexRdi
} Index;

byte modrm(byte mod, byte rm, byte reg) {
  return ((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7);
}

byte sib(Register base, Index index, Scale scale) {
  return ((scale & 0x3) << 6) | ((index & 0x7) << 3) | (base & 0x7);
}

void Emit_mov_reg_imm32(Buffer *buf, Register dst, int32_t src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0xc7);
  Buffer_write8(buf, modrm(kModDirect, dst, 0));
  Buffer_write32(buf, src);
}

void Emit_ret(Buffer *buf) { Buffer_write8(buf, 0xc3); }

void Emit_add_reg_imm32(Buffer *buf, Register dst, int32_t src) {
  Buffer_write8(buf, kRexPrefix);
  if (dst == kRax) {
    // Optimization: add eax, {imm32} can either be encoded as 05 {imm32} or 81
    // c0 {imm32}.
    Buffer_write8(buf, 0x05);
  } else {
    Buffer_write8(buf, 0x81);
    Buffer_write8(buf, modrm(kModDirect, dst, 0));
  }
  Buffer_write32(buf, src);
}

void Emit_sub_reg_imm32(Buffer *buf, Register dst, int32_t src) {
  Buffer_write8(buf, kRexPrefix);
  if (dst == kRax) {
    // Optimization: sub eax, {imm32} can either be encoded as 2d {imm32} or 81
    // e8 {imm32}.
    Buffer_write8(buf, 0x2d);
  } else {
    Buffer_write8(buf, 0x81);
    Buffer_write8(buf, modrm(kModDirect, dst, 5));
  }
  Buffer_write32(buf, src);
}

void Emit_shl_reg_imm8(Buffer *buf, Register dst, int8_t bits) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0xc1);
  Buffer_write8(buf, modrm(kModDirect, dst, 4));
  Buffer_write8(buf, bits);
}

void Emit_shr_reg_imm8(Buffer *buf, Register dst, int8_t bits) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0xc1);
  Buffer_write8(buf, modrm(kModDirect, dst, 5));
  Buffer_write8(buf, bits);
}

void Emit_or_reg_imm8(Buffer *buf, Register dst, uint8_t tag) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x83);
  Buffer_write8(buf, modrm(kModDirect, dst, 1));
  Buffer_write8(buf, tag);
}

void Emit_and_reg_imm8(Buffer *buf, Register dst, uint8_t tag) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x83);
  Buffer_write8(buf, modrm(kModDirect, dst, 4));
  Buffer_write8(buf, tag);
}

void Emit_cmp_reg_imm32(Buffer *buf, Register left, int32_t right) {
  Buffer_write8(buf, kRexPrefix);
  if (left == kRax) {
    // Optimization: cmp rax, {imm32} can either be encoded as 3d {imm32} or 81
    // f8 {imm32}.
    Buffer_write8(buf, 0x3d);
  } else {
    Buffer_write8(buf, 0x81);
    Buffer_write8(buf, modrm(kModDirect, left, 7));
  }
  Buffer_write32(buf, right);
}

void Emit_setcc_imm8(Buffer *buf, Condition cond, PartialRegister dst) {
  // TODO(max): Emit a REX prefix if we need anything above RDI.
  Buffer_write8(buf, 0x0f);
  Buffer_write8(buf, 0x90 + cond);
  Buffer_write8(buf, 0xc0 + (dst & 0x7));
}

uint8_t disp8(int8_t disp) { return disp >= 0 ? disp : 0x100 + disp; }

void Emit_address_disp8(Buffer *buf, Register direct, Indirect indirect) {
  if (indirect.reg == kRsp) {
    Buffer_write8(buf, modrm(kModDisp8, kIndexNone, direct));
    Buffer_write8(buf, sib(kRsp, kIndexNone, Scale1));
  } else {
    Buffer_write8(buf, modrm(kModDisp8, indirect.reg, direct));
  }
  Buffer_write8(buf, disp8(indirect.disp));
}

// mov [dst+disp], src
// or
// mov %src, disp(%dst)
void Emit_store_reg_indirect(Buffer *buf, Indirect dst, Register src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x89);
  Emit_address_disp8(buf, src, dst);
}

// add dst, [src+disp]
// or
// add disp(%src), %dst
void Emit_add_reg_indirect(Buffer *buf, Register dst, Indirect src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x03);
  Emit_address_disp8(buf, dst, src);
}

// sub dst, [src+disp]
// or
// sub disp(%src), %dst
void Emit_sub_reg_indirect(Buffer *buf, Register dst, Indirect src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x2b);
  Emit_address_disp8(buf, dst, src);
}

// mul rax, [src+disp]
// or
// mul disp(%src), %rax
void Emit_mul_reg_indirect(Buffer *buf, Indirect src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0xf7);
  Emit_address_disp8(buf, /*subop*/ 4, src);
}

// cmp left, [right+disp]
// or
// cmp disp(%right), %left
void Emit_cmp_reg_indirect(Buffer *buf, Register left, Indirect right) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x3b);
  Emit_address_disp8(buf, left, right);
}

// mov dst, [src+disp]
// or
// mov disp(%src), %dst
void Emit_load_reg_indirect(Buffer *buf, Register dst, Indirect src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x8b);
  Emit_address_disp8(buf, dst, src);
}

uint32_t disp32(int32_t disp) { return disp >= 0 ? disp : 0x100000000 + disp; }

word Emit_jcc(Buffer *buf, Condition cond, int32_t offset) {
  Buffer_write8(buf, 0x0f);
  Buffer_write8(buf, 0x80 + cond);
  word pos = Buffer_len(buf);
  Buffer_write32(buf, disp32(offset));
  return pos;
}

word Emit_jmp(Buffer *buf, int32_t offset) {
  Buffer_write8(buf, 0xe9);
  word pos = Buffer_len(buf);
  Buffer_write32(buf, disp32(offset));
  return pos;
}

void Emit_backpatch_imm32(Buffer *buf, int32_t target_pos) {
  word current_pos = Buffer_len(buf);
  word relative_pos = current_pos - target_pos - sizeof(int32_t);
  Buffer_at_put32(buf, target_pos, disp32(relative_pos));
}

void Emit_mov_reg_reg(Buffer *buf, Register dst, Register src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0x89);
  Buffer_write8(buf, modrm(kModDirect, dst, src));
}

// mov [dst+disp], imm32
// or
// mov imm32, disp(%dst)
void Emit_store_indirect_imm32(Buffer *buf, Indirect dst, int32_t src) {
  Buffer_write8(buf, kRexPrefix);
  Buffer_write8(buf, 0xc7);
  Emit_address_disp8(buf, /*/0*/ 0, dst);
  Buffer_write32(buf, src);
}

void Emit_rsp_adjust(Buffer *buf, word adjust) {
  if (adjust < 0) {
    Emit_sub_reg_imm32(buf, kRsp, -adjust);
  } else if (adjust > 0) {
    Emit_add_reg_imm32(buf, kRsp, adjust);
  }
}

void Emit_call_imm32(Buffer *buf, word absolute_address) {
  // 5 is length of call instruction
  word relative_address = absolute_address - (Buffer_len(buf) + 5);
  Buffer_write8(buf, 0xe8);
  Buffer_write32(buf, relative_address);
}

void Emit_call_indirect(Buffer *buf, Indirect target) {
  assert(target.reg != kRsp);
  Buffer_write8(buf, 0xff);
  Buffer_write8(buf, modrm(kModDisp32, target.reg, kNear));
  Buffer_write32(buf, target.disp);
}

void Emit_call_reg(Buffer *buf, Register reg) {
  assert(reg != kRsp);
  Buffer_write8(buf, 0xff);
  Buffer_write8(buf, modrm(kModDirect, reg, kNear));
}

// End Emit

// AST

typedef struct ASTNode ASTNode;

typedef struct Pair {
  ASTNode *car;
  ASTNode *cdr;
} Pair;

typedef struct Symbol {
  word length;
  char cstr[];
} Symbol;

bool AST_is_integer(ASTNode *node) {
  return ((uword)node & kIntegerTagMask) == kIntegerTag;
}

word AST_get_integer(ASTNode *node) {
  return Object_decode_integer((uword)node);
}

ASTNode *AST_new_integer(word value) {
  return (ASTNode *)Object_encode_integer(value);
}

bool AST_is_char(ASTNode *node) {
  return ((uword)node & kImmediateTagMask) == kCharTag;
}

char AST_get_char(ASTNode *node) { return Object_decode_char((uword)node); }

ASTNode *AST_new_char(char value) {
  return (ASTNode *)Object_encode_char(value);
}

bool AST_is_bool(ASTNode *node) {
  return ((uword)node & kImmediateTagMask) == kBoolTag;
}

bool AST_get_bool(ASTNode *node) { return Object_decode_bool((uword)node); }

ASTNode *AST_new_bool(bool value) {
  return (ASTNode *)Object_encode_bool(value);
}

bool AST_is_nil(ASTNode *node) { return (uword)node == Object_nil(); }

ASTNode *AST_nil() { return (ASTNode *)Object_nil(); }

bool AST_is_error(ASTNode *node) { return (uword)node == Object_error(); }

ASTNode *AST_error() { return (ASTNode *)Object_error(); }

ASTNode *AST_heap_alloc(unsigned char tag, uword size) {
  // Initialize to 0
  void *address = calloc(size, 1);
  assert(address != NULL && "allocation failed");
  return (ASTNode *)((uword)address | tag);
}

bool AST_is_heap_object(ASTNode *node) {
  // For some reason masking out the tag first and then doing the comparison
  // makes this branchless
  unsigned char tag = (uword)node & kHeapTagMask;
  // Heap object tags are between 0b001 and 0b110 except for 0b100 (which is an
  // integer)
  return (tag & kIntegerTagMask) > 0 && (tag & kImmediateTagMask) != 0x7;
}

void AST_pair_set_car(ASTNode *node, ASTNode *car);
void AST_pair_set_cdr(ASTNode *node, ASTNode *cdr);

ASTNode *AST_new_pair(ASTNode *car, ASTNode *cdr) {
  ASTNode *node = AST_heap_alloc(kPairTag, sizeof(Pair));
  AST_pair_set_car(node, car);
  AST_pair_set_cdr(node, cdr);
  return node;
}

bool AST_is_pair(ASTNode *node) {
  return ((uword)node & kHeapTagMask) == kPairTag;
}

Pair *AST_as_pair(ASTNode *node) {
  assert(AST_is_pair(node));
  return (Pair *)Object_address(node);
}

ASTNode *AST_pair_car(ASTNode *node) { return AST_as_pair(node)->car; }

void AST_pair_set_car(ASTNode *node, ASTNode *car) {
  AST_as_pair(node)->car = car;
}

ASTNode *AST_pair_cdr(ASTNode *node) { return AST_as_pair(node)->cdr; }

void AST_pair_set_cdr(ASTNode *node, ASTNode *cdr) {
  AST_as_pair(node)->cdr = cdr;
}

void AST_heap_free(ASTNode *node) {
  if (!AST_is_heap_object(node)) {
    return;
  }
  if (AST_is_pair(node)) {
    AST_heap_free(AST_pair_car(node));
    AST_heap_free(AST_pair_cdr(node));
  }
  free((void *)Object_address(node));
}

Symbol *AST_as_symbol(ASTNode *node);

ASTNode *AST_new_symbol(const char *str) {
  word data_length = strlen(str) + 1; // for NUL
  ASTNode *node = AST_heap_alloc(kSymbolTag, sizeof(Symbol) + data_length);
  Symbol *s = AST_as_symbol(node);
  s->length = data_length;
  memcpy(s->cstr, str, data_length);
  return node;
}

bool AST_is_symbol(ASTNode *node) {
  return ((uword)node & kHeapTagMask) == kSymbolTag;
}

Symbol *AST_as_symbol(ASTNode *node) {
  assert(AST_is_symbol(node));
  return (Symbol *)Object_address(node);
}

const char *AST_symbol_cstr(ASTNode *node) {
  return (const char *)AST_as_symbol(node)->cstr;
}

bool AST_symbol_matches(ASTNode *node, const char *cstr) {
  return strcmp(AST_symbol_cstr(node), cstr) == 0;
}

int node_to_str(ASTNode *node, char *buf, word size);

int list_to_str(ASTNode *node, char *buf, word size) {
  if (AST_is_pair(node)) {
    word result = 0;
    result += snprintf(buf + result, size, " ");
    result += node_to_str(AST_pair_car(node), buf + result, size);
    result += list_to_str(AST_pair_cdr(node), buf + result, size);
    return result;
  }
  if (AST_is_nil(node)) {
    return snprintf(buf, size, ")");
  }
  word result = 0;
  result += snprintf(buf + result, size, " . ");
  result += node_to_str(node, buf + result, size);
  result += snprintf(buf + result, size, ")");
  return result;
}

int node_to_str(ASTNode *node, char *buf, word size) {
  if (AST_is_integer(node)) {
    return snprintf(buf, size, "%ld", AST_get_integer(node));
  }
  if (AST_is_char(node)) {
    return snprintf(buf, size, "'%c'", AST_get_char(node));
  }
  if (AST_is_bool(node)) {
    return snprintf(buf, size, "%s", AST_get_bool(node) ? "true" : "false");
  }
  if (AST_is_nil(node)) {
    return snprintf(buf, size, "nil");
  }
  if (AST_is_pair(node)) {
    word result = 0;
    result += snprintf(buf + result, size, "(");
    result += node_to_str(AST_pair_car(node), buf + result, size);
    result += list_to_str(AST_pair_cdr(node), buf + result, size);
    return result;
  }
  if (AST_is_symbol(node)) {
    return snprintf(buf, size, "%s", AST_symbol_cstr(node));
  }
  assert(0 && "unknown ast");
}

char *AST_to_cstr(ASTNode *node) {
  int size = node_to_str(node, NULL, 0);
  char *buf = malloc(size + 1);
  assert(buf != NULL);
  node_to_str(node, buf, size + 1);
  buf[size] = '\0';
  return buf;
}

// End AST

// Reader

void advance(word *pos) { ++*pos; }

char next(char *input, word *pos) {
  advance(pos);
  return input[*pos];
}

ASTNode *read_integer(char *input, word *pos, int sign) {
  word result = 0;
  for (char c = input[*pos]; isdigit(c); c = next(input, pos)) {
    result *= 10;
    result += c - '0';
  }
  return AST_new_integer(sign * result);
}

bool starts_symbol(char c) {
  switch (c) {
  case '+':
  case '-':
  case '*':
  case '<':
  case '>':
  case '=':
  case '?':
    return true;
  default:
    return isalpha(c);
  }
}

bool is_symbol_char(char c) { return starts_symbol(c) || isdigit(c); }

const word ATOM_MAX = 32;

ASTNode *read_symbol(char *input, word *pos) {
  char buf[ATOM_MAX + 1]; // +1 for NUL
  word length = 0;
  for (length = 0; length < ATOM_MAX && is_symbol_char(input[*pos]); length++) {
    buf[length] = input[*pos];
    advance(pos);
  }
  buf[length] = '\0';
  return AST_new_symbol(buf);
}

ASTNode *read_char(char *input, word *pos) {
  char c = input[*pos];
  if (c == '\'') {
    return AST_error();
  }
  advance(pos);
  if (input[*pos] != '\'') {
    return AST_error();
  }
  advance(pos);
  return AST_new_char(c);
}

char skip_whitespace(char *input, word *pos) {
  char c = '\0';
  for (c = input[*pos]; isspace(c); c = next(input, pos)) {
    ;
  }
  return c;
}

ASTNode *read_rec(char *input, word *pos);

ASTNode *read_list(char *input, word *pos) {
  char c = skip_whitespace(input, pos);
  if (c == ')') {
    advance(pos);
    return AST_nil();
  }
  ASTNode *car = read_rec(input, pos);
  assert(car != AST_error());
  ASTNode *cdr = read_list(input, pos);
  assert(cdr != AST_error());
  return AST_new_pair(car, cdr);
}

ASTNode *read_rec(char *input, word *pos) {
  char c = skip_whitespace(input, pos);
  if (isdigit(c)) {
    return read_integer(input, pos, /*sign=*/1);
  }
  if (c == '-' && isdigit(input[*pos + 1])) {
    advance(pos);
    return read_integer(input, pos, /*sign=*/-1);
  }
  if (c == '+' && isdigit(input[*pos + 1])) {
    advance(pos);
    return read_integer(input, pos, /*sign=*/1);
  }
  if (starts_symbol(c)) {
    return read_symbol(input, pos);
  }
  if (c == '\'') {
    advance(pos); // skip '\''
    return read_char(input, pos);
  }
  if (c == '#' && input[*pos + 1] == 't') {
    advance(pos); // skip '#'
    advance(pos); // skip 't'
    return AST_new_bool(true);
  }
  if (c == '#' && input[*pos + 1] == 'f') {
    advance(pos); // skip '#'
    advance(pos); // skip 'f'
    return AST_new_bool(false);
  }
  if (c == '(') {
    advance(pos); // skip '('
    return read_list(input, pos);
  }
  return AST_error();
}

ASTNode *Reader_read(char *input) {
  word pos = 0;
  return read_rec(input, &pos);
}

// End Reader

// Transformer

ASTNode *operand1(ASTNode *args) { return AST_pair_car(args); }

ASTNode *operand2(ASTNode *args) { return AST_pair_car(AST_pair_cdr(args)); }

ASTNode *operand3(ASTNode *args) {
  return AST_pair_car(AST_pair_cdr(AST_pair_cdr(args)));
}

static word gensym_idx = 0;

word gensym_next() { return gensym_idx++; }

void gensym_reset() { gensym_idx = 0; }

const char *gensym() {
  char buf[128];
  snprintf(buf, sizeof buf, "f%ld", gensym_next());
  return strdup(buf);
}

bool set_contains(ASTNode *set, const char *name) {
  if (AST_is_nil(set)) {
    return false;
  }
  assert(AST_is_pair(set));
  ASTNode *elt = AST_pair_car(set);
  if (AST_symbol_matches(elt, name)) {
    return true;
  }
  return set_contains(AST_pair_cdr(set), name);
}

ASTNode *set_merge(ASTNode *left, ASTNode *right) {
  if (AST_is_nil(left)) {
    return right;
  }
  ASTNode *elt = AST_pair_car(left);
  ASTNode *rest = AST_pair_cdr(left);
  const char *name = AST_symbol_cstr(elt);
  if (set_contains(rest, name) || set_contains(right, name)) {
    return set_merge(rest, right);
  }
  return AST_new_pair(elt, set_merge(AST_pair_cdr(left), right));
}

typedef ASTNode *MapFunction(ASTNode *node);

ASTNode *map(MapFunction fn, ASTNode *node) {
  if (AST_is_nil(node)) {
    return node;
  }
  ASTNode *elt = AST_pair_car(node);
  return AST_new_pair((*fn)(elt), map(fn, AST_pair_cdr(node)));
}

ASTNode *free_in_rec(ASTNode *node, ASTNode *bound) {
  if (AST_is_integer(node) || AST_is_char(node) || AST_is_bool(node) ||
      AST_is_nil(node)) {
    // Nothing free; nothing referenced
    return AST_nil();
  }
  if (AST_is_symbol(node)) {
    if (AST_symbol_matches(node, "if") || AST_symbol_matches(node, "let") ||
        AST_symbol_matches(node, "lambda") ||
        AST_symbol_matches(node, "closure") ||
        AST_symbol_matches(node, "quote") || AST_symbol_matches(node, "+") ||
        AST_symbol_matches(node, "apply")) {
      // Nothing free; special names are not variable references
      return AST_nil();
    }
    if (set_contains(bound, AST_symbol_cstr(node))) {
      // Nothing free; name is bound
      return AST_nil();
    }
    return AST_new_pair(node, AST_nil());
  }
  assert(AST_is_pair(node));
  ASTNode *callable = AST_pair_car(node);
  ASTNode *args = AST_pair_cdr(node);
  if (AST_is_symbol(callable)) {
    // Handle special forms that bind variables
    if (AST_symbol_matches(callable, "let")) {
      ASTNode *bindings = operand1(args);
      ASTNode *freevars_bindings = AST_nil();
      ASTNode *bindings_names = map(AST_pair_car, bindings);
      while (!AST_is_nil(bindings)) {
        ASTNode *binding_value = AST_pair_cdr(AST_pair_car(bindings));
        freevars_bindings =
            set_merge(freevars_bindings, free_in_rec(binding_value, bound));
        bindings = AST_pair_cdr(bindings);
      }
      ASTNode *body = operand2(args);
      ASTNode *new_bound = set_merge(bindings_names, bound);
      ASTNode *freevars_body = free_in_rec(body, new_bound);
      return set_merge(freevars_bindings, freevars_body);
    }
    if (AST_symbol_matches(callable, "lambda")) {
      ASTNode *params = operand1(args);
      ASTNode *body = operand2(args);
      return free_in_rec(body, set_merge(bound, params));
    }
  }
  // Handle some call (fn arg0 arg1 ...)
  ASTNode *freevars = free_in_rec(callable, bound);
  while (!AST_is_nil(args)) {
    assert(AST_is_pair(args));
    ASTNode *arg = AST_pair_car(args);
    freevars = set_merge(freevars, free_in_rec(arg, bound));
    args = AST_pair_cdr(args);
  }
  return freevars;
}

ASTNode *free_in(ASTNode *node) { return free_in_rec(node, AST_nil()); }

ASTNode *list1(ASTNode *item0) { return AST_new_pair(item0, AST_nil()); }

ASTNode *list2(ASTNode *item0, ASTNode *item1) {
  return AST_new_pair(item0, list1(item1));
}

ASTNode *list3(ASTNode *item0, ASTNode *item1, ASTNode *item2) {
  return AST_new_pair(item0, list2(item1, item2));
}

ASTNode *list4(ASTNode *item0, ASTNode *item1, ASTNode *item2, ASTNode *item3) {
  return AST_new_pair(item0, list3(item1, item2, item3));
}

bool is_tagged_with(ASTNode *node, const char *expected) {
  if (!AST_is_pair(node)) {
    return false;
  }
  ASTNode *tag = AST_pair_car(node);
  if (!AST_is_symbol(tag)) {
    return false;
  }
  return AST_symbol_matches(tag, expected);
}

ASTNode *Transform(ASTNode *node);

ASTNode *Transform_lambda(ASTNode *node) {
  assert(is_tagged_with(node, "lambda"));
  ASTNode *args = AST_pair_cdr(node);
  ASTNode *params = operand1(args);
  ASTNode *body = operand2(args);
  ASTNode *freevars = free_in_rec(body, params);
  return list4(AST_new_symbol("lambda"), params, freevars, Transform(body));
}

ASTNode *Transform_binding(ASTNode *binding) {
  ASTNode *name = AST_pair_car(binding);
  ASTNode *value = AST_pair_car(AST_pair_cdr(binding));
  return list2(name, Transform(value));
}

ASTNode *Transform(ASTNode *node) {
  if (AST_is_integer(node) || AST_is_char(node) || AST_is_bool(node) ||
      AST_is_nil(node) || AST_is_symbol(node)) {
    // Nothing to traverse and transform
    return node;
  }
  if (is_tagged_with(node, "lambda")) {
    return Transform_lambda(node);
  }
  if (is_tagged_with(node, "let")) {
    ASTNode *args = AST_pair_cdr(node);
    ASTNode *bindings = operand1(args);
    ASTNode *body = operand2(args);
    return list3(AST_pair_car(node), map(Transform_binding, (bindings)),
                 Transform(body));
  }
  return map(Transform, node);
}

// End Transformer

// Env

typedef struct Env {
  const char *name;
  word value;
  struct Env *prev;
} Env;

Env Env_bind(const char *name, word value, Env *prev) {
  return (Env){.name = name, .value = value, .prev = prev};
}

bool Env_find(Env *env, const char *key, word *result) {
  if (env == NULL)
    return false;
  if (strcmp(env->name, key) == 0) {
    *result = env->value;
    return true;
  }
  return Env_find(env->prev, key, result);
}

// End Env

// Compile

WARN_UNUSED int Compile_expr(Buffer *buf, ASTNode *node, word stack_index,
                             Env *varenv, Env *labels);

#define _(exp)                                                                 \
  do {                                                                         \
    int result = exp;                                                          \
    if (result != 0)                                                           \
      return result;                                                           \
  } while (0)

void Compile_compare_imm32(Buffer *buf, int32_t value) {
  Emit_cmp_reg_imm32(buf, kRax, value);
  Emit_mov_reg_imm32(buf, kRax, 0);
  Emit_setcc_imm8(buf, kEqual, kAl);
  Emit_shl_reg_imm8(buf, kRax, kBoolShift);
  Emit_or_reg_imm8(buf, kRax, kBoolTag);
}

// This is let, not let*. Therefore we keep track of two environments -- the
// parent environment, for evaluating the bindings, and the body environment,
// which will have all of the bindings in addition to the parent. This makes
// programs like (let ((a 1) (b a)) b) fail.
WARN_UNUSED int Compile_let(Buffer *buf, ASTNode *bindings, ASTNode *body,
                            word stack_index, Env *binding_env, Env *body_env,
                            Env *labels) {
  if (AST_is_nil(bindings)) {
    // Base case: no bindings. Compile the body
    _(Compile_expr(buf, body, stack_index, body_env, labels));
    return 0;
  }
  assert(AST_is_pair(bindings));
  // Get the next binding
  ASTNode *binding = AST_pair_car(bindings);
  ASTNode *name = AST_pair_car(binding);
  assert(AST_is_symbol(name));
  ASTNode *binding_expr = AST_pair_car(AST_pair_cdr(binding));
  // Compile the binding expression
  _(Compile_expr(buf, binding_expr, stack_index, binding_env, labels));
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                          /*src=*/kRax);
  // Bind the name
  Env entry = Env_bind(AST_symbol_cstr(name), stack_index, body_env);
  _(Compile_let(buf, AST_pair_cdr(bindings), body, stack_index - kWordSize,
                /*binding_env=*/binding_env, /*body_env=*/&entry, labels));
  return 0;
}

const int32_t kLabelPlaceholder = 0xdeadbeef;

WARN_UNUSED int Compile_if(Buffer *buf, ASTNode *cond, ASTNode *consequent,
                           ASTNode *alternate, word stack_index, Env *varenv,
                           Env *labels) {
  _(Compile_expr(buf, cond, stack_index, varenv, labels));
  Emit_cmp_reg_imm32(buf, kRax, Object_false());
  word alternate_pos = Emit_jcc(buf, kEqual, kLabelPlaceholder); // je alternate
  _(Compile_expr(buf, consequent, stack_index, varenv, labels));
  word end_pos = Emit_jmp(buf, kLabelPlaceholder); // jmp end
  Emit_backpatch_imm32(buf, alternate_pos);        // alternate:
  _(Compile_expr(buf, alternate, stack_index, varenv, labels));
  Emit_backpatch_imm32(buf, end_pos); // end:
  return 0;
}

const Register kHeapPointer = kRsi;
const Register kClosurePointer = kRdi;
const Register kCodePointer = kRcx;

WARN_UNUSED int Compile_cons(Buffer *buf, ASTNode *car, ASTNode *cdr,
                             word stack_index, Env *varenv, Env *labels) {
  // Compile and store car on the stack
  _(Compile_expr(buf, car, stack_index, varenv, labels));
  Emit_store_reg_indirect(buf,
                          /*dst=*/Ind(kRsp, stack_index),
                          /*src=*/kRax);
  // Compile and store cdr
  _(Compile_expr(buf, cdr, stack_index - kWordSize, varenv, labels));
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kHeapPointer, kCdrOffset),
                          /*src=*/kRax);
  // Fetch car and store in the heap
  Emit_load_reg_indirect(buf, /*dst=*/kRax, /*src=*/Ind(kRsp, stack_index));
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kHeapPointer, kCarOffset),
                          /*src=*/kRax);
  // Store tagged pointer in rax
  // TODO(max): Rewrite as lea rax, [Heap+kPairTag]
  Emit_mov_reg_reg(buf, /*dst=*/kRax, /*src=*/kHeapPointer);
  Emit_or_reg_imm8(buf, /*dst=*/kRax, kPairTag);
  // Bump the heap pointer
  Emit_add_reg_imm32(buf, /*dst=*/kHeapPointer, kPairSize);
  return 0;
}

word list_length(ASTNode *node) {
  if (AST_is_nil(node)) {
    return 0;
  }
  assert(AST_is_pair(node));
  return 1 + list_length(AST_pair_cdr(node));
}

WARN_UNUSED int Compile_funcall(Buffer *buf, ASTNode *callable, ASTNode *args,
                                word stack_index, Env *varenv, Env *labels,
                                word closure_index) {
  if (AST_is_nil(args)) {
    // This should result in a closure
    return Compile_expr(buf, callable, stack_index, varenv, labels);
  }
  assert(AST_is_pair(args));
  ASTNode *arg = AST_pair_car(args);
  _(Compile_expr(buf, arg, stack_index, varenv, labels));
  Emit_store_reg_indirect(buf, Ind(kRsp, stack_index), kRax);
  return Compile_funcall(buf, callable, AST_pair_cdr(args),
                         stack_index - kWordSize, varenv, labels,
                         closure_index);
}

WARN_UNUSED int Compile_closure(Buffer *buf, ASTNode *freevars,
                                word stack_index, word closure_index,
                                Env *varenv, Env *labels) {
  if (AST_is_nil(freevars)) {
    return 0;
  }
  assert(AST_is_pair(freevars));
  ASTNode *freevar = AST_pair_car(freevars);
  _(Compile_expr(buf, freevar, stack_index, varenv, labels));
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index), /*src=*/kRax);
  _(Compile_closure(buf, AST_pair_cdr(freevars), stack_index - kWordSize,
                    closure_index + kWordSize, varenv, labels));
  Emit_load_reg_indirect(buf, /*dst=*/kRax, /*src=*/Ind(kRsp, stack_index));
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kHeapPointer, closure_index),
                          /*src=*/kRax);
  return 0;
}

WARN_UNUSED int Compile_call(Buffer *buf, ASTNode *callable, ASTNode *args,
                             word stack_index, Env *varenv, Env *labels) {
  if (AST_is_symbol(callable)) {
    if (AST_symbol_matches(callable, "add1")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_add_reg_imm32(buf, kRax, Object_encode_integer(1));
      return 0;
    }
    if (AST_symbol_matches(callable, "sub1")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_sub_reg_imm32(buf, kRax, Object_encode_integer(1));
      return 0;
    }
    if (AST_symbol_matches(callable, "integer->char")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_shl_reg_imm8(buf, kRax, kCharShift - kIntegerShift);
      Emit_or_reg_imm8(buf, kRax, kCharTag);
      return 0;
    }
    if (AST_symbol_matches(callable, "char->integer")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_shr_reg_imm8(buf, kRax, kCharShift - kIntegerShift);
      return 0;
    }
    if (AST_symbol_matches(callable, "nil?")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Compile_compare_imm32(buf, Object_nil());
      return 0;
    }
    if (AST_symbol_matches(callable, "zero?")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Compile_compare_imm32(buf, Object_encode_integer(0));
      return 0;
    }
    if (AST_symbol_matches(callable, "not")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      // All non #f values are truthy
      // ...this might be a problem if we want to make nil falsey
      Compile_compare_imm32(buf, Object_false());
      return 0;
    }
    if (AST_symbol_matches(callable, "integer?")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_and_reg_imm8(buf, kRax, kIntegerTagMask);
      Compile_compare_imm32(buf, kIntegerTag);
      return 0;
    }
    if (AST_symbol_matches(callable, "boolean?")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_and_reg_imm8(buf, kRax, kImmediateTagMask);
      Compile_compare_imm32(buf, kBoolTag);
      return 0;
    }
    if (AST_symbol_matches(callable, "+")) {
      _(Compile_expr(buf, operand2(args), stack_index, varenv, labels));
      Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                              /*src=*/kRax);
      _(Compile_expr(buf, operand1(args), stack_index - kWordSize, varenv,
                     labels));
      Emit_add_reg_indirect(buf, /*dst=*/kRax, /*src=*/Ind(kRsp, stack_index));
      return 0;
    }
    if (AST_symbol_matches(callable, "-")) {
      _(Compile_expr(buf, operand2(args), stack_index, varenv, labels));
      Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                              /*src=*/kRax);
      _(Compile_expr(buf, operand1(args), stack_index - kWordSize, varenv,
                     labels));
      Emit_sub_reg_indirect(buf, /*dst=*/kRax, /*src=*/Ind(kRsp, stack_index));
      return 0;
    }
    if (AST_symbol_matches(callable, "*")) {
      _(Compile_expr(buf, operand2(args), stack_index, varenv, labels));
      // Remove the tag so that the result is still only tagged with 0b00
      // instead of 0b0000
      Emit_shr_reg_imm8(buf, kRax, kIntegerShift);
      Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                              /*src=*/kRax);
      _(Compile_expr(buf, operand1(args), stack_index - kWordSize, varenv,
                     labels));
      Emit_mul_reg_indirect(buf, /*src=*/Ind(kRsp, stack_index));
      return 0;
    }
    if (AST_symbol_matches(callable, "=")) {
      _(Compile_expr(buf, operand2(args), stack_index, varenv, labels));
      Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                              /*src=*/kRax);
      _(Compile_expr(buf, operand1(args), stack_index - kWordSize, varenv,
                     labels));
      Emit_cmp_reg_indirect(buf, kRax, Ind(kRsp, stack_index));
      Emit_mov_reg_imm32(buf, kRax, 0);
      Emit_setcc_imm8(buf, kEqual, kAl);
      Emit_shl_reg_imm8(buf, kRax, kBoolShift);
      Emit_or_reg_imm8(buf, kRax, kBoolTag);
      return 0;
    }
    if (AST_symbol_matches(callable, "<")) {
      _(Compile_expr(buf, operand2(args), stack_index, varenv, labels));
      Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, stack_index),
                              /*src=*/kRax);
      _(Compile_expr(buf, operand1(args), stack_index - kWordSize, varenv,
                     labels));
      Emit_cmp_reg_indirect(buf, kRax, Ind(kRsp, stack_index));
      Emit_mov_reg_imm32(buf, kRax, 0);
      Emit_setcc_imm8(buf, kLess, kAl);
      Emit_shl_reg_imm8(buf, kRax, kBoolShift);
      Emit_or_reg_imm8(buf, kRax, kBoolTag);
      return 0;
    }
    if (AST_symbol_matches(callable, "let")) {
      return Compile_let(buf, /*bindings=*/operand1(args),
                         /*body=*/operand2(args), stack_index,
                         /*binding_env=*/varenv,
                         /*body_env=*/varenv, labels);
    }
    if (AST_symbol_matches(callable, "if")) {
      return Compile_if(buf, /*condition=*/operand1(args),
                        /*consequent=*/operand2(args),
                        /*alternate=*/operand3(args), stack_index, varenv,
                        labels);
    }
    if (AST_symbol_matches(callable, "cons")) {
      return Compile_cons(buf, /*car=*/operand1(args), /*cdr=*/operand2(args),
                          stack_index, varenv, labels);
    }
    if (AST_symbol_matches(callable, "car")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_load_reg_indirect(buf, /*dst=*/kRax,
                             /*src=*/Ind(kRax, kCarOffset - kPairTag));
      return 0;
    }
    if (AST_symbol_matches(callable, "cdr")) {
      _(Compile_expr(buf, operand1(args), stack_index, varenv, labels));
      Emit_load_reg_indirect(buf, /*dst=*/kRax,
                             /*src=*/Ind(kRax, kCdrOffset - kPairTag));
      return 0;
    }
    if (AST_symbol_matches(callable, "closure")) {
      // Closures look like (closure label freevar0 freevar1 freevar2 ...)
      ASTNode *label = operand1(args);
      assert(AST_is_symbol(label));
      word code_address;
      if (!Env_find(labels, AST_symbol_cstr(label), &code_address)) {
        return -1;
      }
      ASTNode *freevars = AST_pair_cdr(args);
      word num_freevars = list_length(freevars);
      // TODO(max): Decide if the entire heap should be parseable, and
      // code_address should be encoded as an integer, or if it should just
      // be output as-is.
      _(Compile_closure(buf, freevars, stack_index, /*closure_index=*/kWordSize,
                        varenv, labels));
      // Add the code section address to the section offset of the code
      Emit_mov_reg_reg(buf, /*dst=*/kRax, /*src=*/kCodePointer);
      Emit_add_reg_imm32(buf, /*dst=*/kRax, code_address);
      // Closure is now in kHeapPointer; store the code
      Emit_store_reg_indirect(buf,
                              /*dst=*/Ind(kHeapPointer, kClosureLabelOffset),
                              /*src=*/kRax);
      // Tag the pointer in rax
      Emit_mov_reg_reg(buf, /*dst=*/kRax, /*src=*/kHeapPointer);
      Emit_or_reg_imm8(buf, /*dst=*/kRax, kClosureTag);
      Emit_add_reg_imm32(buf, /*dst=*/kHeapPointer,
                         (num_freevars + 1) * kWordSize);
      return 0;
    }
  }

  // * Evaluate all the arguments and save to the stack
  // * Save two stack locations: closure pointer, return point
  // * Evaluate the callable/operator
  //   * Save the old value to the stack in current frame (?)
  //   * Move the callable's closure pointer to rdi
  // * Adjust rsp; make sure return point is at [rsp-0]
  // * Call closure[label]
  // * Adjust rsp
  // * Restore calling frame's rdi from stack

  // Skip two spaces on the stack to put the return address and closure
  // pointer
  word closure_stack_index = stack_index;
  word return_point_index = closure_stack_index - kWordSize;
  word arg_stack_index = return_point_index - kWordSize;
  // Compile arguments and callable
  _(Compile_funcall(buf, callable, args, arg_stack_index, varenv, labels,
                    closure_stack_index));
  // Save the current closure pointer to the stack so that it can be restored
  // after the call
  Emit_store_reg_indirect(buf, /*dst=*/Ind(kRsp, closure_stack_index),
                          /*src=*/kClosurePointer);
  // Set the closure pointer for the new call frame with tag removed
  Emit_mov_reg_reg(buf, /*dst=*/kClosurePointer, /*src=*/kRax);
  Emit_sub_reg_imm32(buf, kClosurePointer, kClosureTag);
  // Put the code pointer in rax so that it can be called
  Emit_load_reg_indirect(buf, /*dst=*/kRax,
                         /*src=*/Ind(kClosurePointer, kClosureLabelOffset));
  // We enter Compile_call with a stack_index pointing to the next
  // available spot on the stack, where we will put the closure pointer. We
  // need to save the locals on the stack as well as the closure pointer. So
  // save everything up to *and* including stack_index.
  // [ 24: next available ]  <-- closure pointer going here
  // [ 16: local          ]
  // [  8: local          ]
  // [  0: return point   ]
  // stack_index is at 24 and rsp is at 0. Save all three slots.
  Emit_rsp_adjust(buf, stack_index);
  Emit_call_reg(buf, kRax);
  Emit_rsp_adjust(buf, -stack_index);
  // Load the saved closure pointer
  Emit_load_reg_indirect(buf, /*dst=*/kClosurePointer,
                         /*src=*/Ind(kRsp, closure_stack_index));
  return 0;
}

WARN_UNUSED int Compile_expr(Buffer *buf, ASTNode *node, word stack_index,
                             Env *varenv, Env *labels) {
  if (AST_is_integer(node)) {
    word value = AST_get_integer(node);
    Emit_mov_reg_imm32(buf, kRax, Object_encode_integer(value));
    return 0;
  }
  if (AST_is_char(node)) {
    char value = AST_get_char(node);
    Emit_mov_reg_imm32(buf, kRax, Object_encode_char(value));
    return 0;
  }
  if (AST_is_bool(node)) {
    bool value = AST_get_bool(node);
    Emit_mov_reg_imm32(buf, kRax, Object_encode_bool(value));
    return 0;
  }
  if (AST_is_nil(node)) {
    Emit_mov_reg_imm32(buf, kRax, Object_nil());
    return 0;
  }
  if (AST_is_pair(node)) {
    return Compile_call(buf, AST_pair_car(node), AST_pair_cdr(node),
                        stack_index, varenv, labels);
  }
  if (AST_is_symbol(node)) {
    const char *symbol = AST_symbol_cstr(node);
    word offset;
    if (Env_find(varenv, symbol, &offset)) {
      assert(offset != 0 && "neither stack variables nor closure variables "
                            "should be at offset 0");
      // If the offset is negative, this is a stack-allocated variable.
      // Otherwise, it is a closure-allocated variable.
      Register reg = offset < 0 ? kRsp : kClosurePointer;
      Emit_load_reg_indirect(buf, /*dst=*/kRax, /*src=*/Ind(reg, offset));
      return 0;
    }
    return -1;
  }
  assert(0 && "unexpected node type");
}

const byte kEntryPrologue[] = {
    // Save the code pointer in rcx, our global code pointer
    // mov kCodePointer, rsi
    kRexPrefix,
    0x8b,
    0xce,
    // Save the heap in rsi, our global heap pointer
    // mov kHeapPointer, rdi
    kRexPrefix,
    0x89,
    0xfe,
};

const byte kFunctionEpilogue[] = {
    // ret
    0xc3,
};

WARN_UNUSED int Compile_code_freevars(Buffer *buf, ASTNode *freevars,
                                      ASTNode *body, word stack_index,
                                      word freevar_index, Env *varenv,
                                      Env *labels) {
  if (AST_is_nil(freevars)) {
    _(Compile_expr(buf, body, stack_index, varenv, labels));
    Buffer_write_arr(buf, kFunctionEpilogue, sizeof kFunctionEpilogue);
    return 0;
  }
  assert(AST_is_pair(freevars));
  ASTNode *name = AST_pair_car(freevars);
  assert(AST_is_symbol(name));
  Env entry = Env_bind(AST_symbol_cstr(name), freevar_index, varenv);
  return Compile_code_freevars(buf, AST_pair_cdr(freevars), body, stack_index,
                               freevar_index + kWordSize, &entry, labels);
}

WARN_UNUSED int Compile_code_formals(Buffer *buf, ASTNode *formals,
                                     ASTNode *freevars, ASTNode *body,
                                     word stack_index, Env *varenv,
                                     Env *labels) {
  if (AST_is_nil(formals)) {
    word freevar_index = kWordSize;
    return Compile_code_freevars(buf, freevars, body, stack_index,
                                 freevar_index, varenv, labels);
  }
  assert(AST_is_pair(formals));
  ASTNode *name = AST_pair_car(formals);
  assert(AST_is_symbol(name));
  Env entry = Env_bind(AST_symbol_cstr(name), stack_index, varenv);
  return Compile_code_formals(buf, AST_pair_cdr(formals), freevars, body,
                              stack_index - kWordSize, &entry, labels);
}

WARN_UNUSED int Compile_code(Buffer *buf, ASTNode *code, Env *labels) {
  assert(AST_is_pair(code));
  ASTNode *code_sym = AST_pair_car(code);
  assert(AST_is_symbol(code_sym));
  assert(AST_symbol_matches(code_sym, "code"));
  ASTNode *args = AST_pair_cdr(code);
  ASTNode *formals = operand1(args);
  ASTNode *freevars = operand2(args);
  ASTNode *code_body = operand3(args);
  return Compile_code_formals(buf, formals, freevars, code_body,
                              /*stack_index=*/-kWordSize,
                              /*varenv=*/NULL, labels);
}

WARN_UNUSED int Compile_labels(Buffer *buf, ASTNode *bindings, ASTNode *body,
                               Env *labels) {
  if (AST_is_nil(bindings)) {
    buf->entrypoint = Buffer_len(buf);
    // Base case: no bindings. Compile the body
    Buffer_write_arr(buf, kEntryPrologue, sizeof kEntryPrologue);
    _(Compile_expr(buf, body, /*stack_index=*/-kWordSize, /*varenv=*/NULL,
                   labels));
    Buffer_write_arr(buf, kFunctionEpilogue, sizeof kFunctionEpilogue);
    return 0;
  }
  assert(AST_is_pair(bindings));
  // Get the next binding
  ASTNode *binding = AST_pair_car(bindings);
  ASTNode *name = AST_pair_car(binding);
  assert(AST_is_symbol(name));
  ASTNode *binding_code = AST_pair_car(AST_pair_cdr(binding));
  word function_location = Buffer_len(buf);
  // Bind the name to the location in the instruction stream
  Env entry = Env_bind(AST_symbol_cstr(name), function_location, labels);
  // Compile the binding function
  _(Compile_code(buf, binding_code, &entry));
  return Compile_labels(buf, AST_pair_cdr(bindings), body, &entry);
}

WARN_UNUSED int Compile_entry(Buffer *buf, ASTNode *node) {
  assert(AST_is_pair(node) && "program must have labels");
  // Assume it's (labels ...)
  ASTNode *labels_sym = AST_pair_car(node);
  assert(AST_is_symbol(labels_sym) && "program must have labels");
  assert(AST_symbol_matches(labels_sym, "labels") &&
         "program must have labels");
  ASTNode *args = AST_pair_cdr(node);
  ASTNode *bindings = operand1(args);
  assert(AST_is_pair(bindings) || AST_is_nil(bindings));
  ASTNode *body = operand2(args);
  return Compile_labels(buf, bindings, body, /*labels=*/NULL);
}

// End Compile

typedef uword (*JitFunction)(uword *heap, byte *code);

// Testing

uword Testing_execute_entry(Buffer *buf, uword *heap) {
  assert(buf != NULL);
  assert(buf->address != NULL);
  assert(buf->state == kExecutable);
  // The pointer-pointer cast is allowed but the underlying
  // data-to-function-pointer back-and-forth is only guaranteed to work on
  // POSIX systems (because of eg dlsym).
  byte *start_address = buf->address + buf->entrypoint;
  JitFunction function = *(JitFunction *)(&start_address);
  return function(heap, buf->address);
}

uword Testing_execute_expr(Buffer *buf) {
  return Testing_execute_entry(buf, /*heap=*/NULL);
}

TEST Testing_expect_entry_has_contents(Buffer *buf, byte *arr,
                                       size_t arr_size) {
  word total_size = sizeof kEntryPrologue + arr_size + sizeof kFunctionEpilogue;
  ASSERT_EQ_FMT(total_size, Buffer_len(buf), "%ld");

  byte *ptr = buf->address;
  ASSERT_MEM_EQ(kEntryPrologue, ptr, sizeof kEntryPrologue);
  ptr += sizeof kEntryPrologue;
  ASSERT_MEM_EQ(arr, ptr, arr_size);
  ptr += arr_size;
  ASSERT_MEM_EQ(kFunctionEpilogue, ptr, sizeof kFunctionEpilogue);
  ptr += sizeof kFunctionEpilogue;
  PASS();
}

WARN_UNUSED int Testing_compile_expr_entry(Buffer *buf, ASTNode *node) {
  Buffer_write_arr(buf, kEntryPrologue, sizeof kEntryPrologue);
  _(Compile_expr(buf, node, /*stack_index=*/-kWordSize, /*varenv=*/NULL,
                 /*labels=*/NULL));
  Buffer_write_arr(buf, kFunctionEpilogue, sizeof kFunctionEpilogue);
  return 0;
}

#define EXPECT_EQUALS_BYTES(buf, arr)                                          \
  ASSERT_EQ_FMT(sizeof arr, Buffer_len(buf), "%ld");                           \
  ASSERT_MEM_EQ(arr, (buf)->address, sizeof arr)

#define EXPECT_ENTRY_CONTAINS_CODE(buf, arr)                                   \
  CHECK_CALL(Testing_expect_entry_has_contents(buf, arr, sizeof arr))

#define RUN_BUFFER_TEST(test_name)                                             \
  do {                                                                         \
    Buffer buf;                                                                \
    Buffer_init(&buf, 1);                                                      \
    GREATEST_RUN_TEST1(test_name, &buf);                                       \
    Buffer_deinit(&buf);                                                       \
  } while (0)

#define RUN_HEAP_TEST(test_name)                                               \
  do {                                                                         \
    Buffer buf;                                                                \
    Buffer_init(&buf, 1);                                                      \
    uword *heap = malloc(1000 * kWordSize);                                    \
    GREATEST_RUN_TESTp(test_name, &buf, heap);                                 \
    free(heap);                                                                \
    Buffer_deinit(&buf);                                                       \
  } while (0)

ASTNode *new_unary_call(const char *name, ASTNode *arg) {
  return list2(AST_new_symbol(name), arg);
}

ASTNode *new_binary_call(const char *name, ASTNode *arg0, ASTNode *arg1) {
  return list3(AST_new_symbol(name), arg0, arg1);
}

// End Testing

// Tests

TEST encode_positive_integer(void) {
  ASSERT_EQ(Object_encode_integer(0), 0x0);
  ASSERT_EQ(Object_encode_integer(1), 0x4);
  ASSERT_EQ(Object_encode_integer(10), 0x28);
  PASS();
}

TEST encode_negative_integer(void) {
  ASSERT_EQ(Object_encode_integer(0), 0x0);
  ASSERT_EQ(Object_encode_integer(-1), 0xfffffffffffffffc);
  ASSERT_EQ(Object_encode_integer(-10), 0xffffffffffffffd8);
  PASS();
}

TEST encode_char(void) {
  ASSERT_EQ(Object_encode_char('\0'), 0xf);
  ASSERT_EQ(Object_encode_char('a'), 0x610f);
  PASS();
}

TEST decode_char(void) {
  ASSERT_EQ(Object_decode_char(0xf), '\0');
  ASSERT_EQ(Object_decode_char(0x610f), 'a');
  PASS();
}

TEST encode_bool(void) {
  ASSERT_EQ(Object_encode_bool(true), 0x9f);
  ASSERT_EQ(Object_encode_bool(false), 0x1f);
  ASSERT_EQ(Object_true(), 0x9f);
  ASSERT_EQ(Object_false(), 0x1f);
  PASS();
}

TEST decode_bool(void) {
  ASSERT_EQ(Object_decode_bool(0x9f), true);
  ASSERT_EQ(Object_decode_bool(0x1f), false);
  PASS();
}

TEST address(void) {
  ASSERT_EQ(Object_address((void *)0xFF01), 0xFF00);
  PASS();
}

TEST emit_mov_reg_imm32_emits_modrm(Buffer *buf) {
  Emit_mov_reg_imm32(buf, kRax, 100);
  byte expected[] = {0x48, 0xc7, 0xc0, 0x64, 0x00, 0x00, 0x00};
  EXPECT_EQUALS_BYTES(buf, expected);
  ASSERT_EQ_FMT(modrm(kModDirect, kRax, 0), 0xc0, "0x%.2x");
  PASS();
}

TEST emit_store_reg_indirect_emits_modrm_sib(Buffer *buf) {
  Emit_store_reg_indirect(buf, Ind(kRsp, -8), kRax);
  byte expected[] = {0x48, 0x89, 0x44, 0x24, 0xf8};
  EXPECT_EQUALS_BYTES(buf, expected);
  ASSERT_EQ_FMT(modrm(kModDisp8, kIndexNone, kRax), 0x44, "0x%.2x");
  ASSERT_EQ_FMT(sib(kRsp, kIndexNone, Scale1), 0x24, "0x%.2x");
  PASS();
}

TEST ast_new_pair(void) {
  ASTNode *node = AST_new_pair(NULL, NULL);
  ASSERT(AST_is_pair(node));
  AST_heap_free(node);
  PASS();
}

TEST ast_pair_car_returns_car(void) {
  ASTNode *node = AST_new_pair(AST_new_integer(123), NULL);
  ASTNode *car = AST_pair_car(node);
  ASSERT(AST_is_integer(car));
  ASSERT_EQ(Object_decode_integer((uword)car), 123);
  AST_heap_free(node);
  PASS();
}

TEST ast_pair_cdr_returns_cdr(void) {
  ASTNode *node = AST_new_pair(NULL, AST_new_integer(123));
  ASTNode *cdr = AST_pair_cdr(node);
  ASSERT(AST_is_integer(cdr));
  ASSERT_EQ(Object_decode_integer((uword)cdr), 123);
  AST_heap_free(node);
  PASS();
}

TEST ast_new_symbol(void) {
  const char *value = "my symbol";
  ASTNode *node = AST_new_symbol(value);
  ASSERT(AST_is_symbol(node));
  ASSERT_STR_EQ(AST_symbol_cstr(node), value);
  AST_heap_free(node);
  PASS();
}

#define ASSERT_IS_CHAR_EQ(node, c)                                             \
  do {                                                                         \
    ASTNode *__tmp = node;                                                     \
    if (AST_is_error(__tmp)) {                                                 \
      fprintf(stderr, "Expected a char but got an error.\n");                  \
    }                                                                          \
    ASSERT(AST_is_char(__tmp));                                                \
    ASSERT_EQ(AST_get_char(__tmp), c);                                         \
  } while (0);

#define ASSERT_IS_INT_EQ(node, val)                                            \
  do {                                                                         \
    ASTNode *__tmp = node;                                                     \
    if (AST_is_error(__tmp)) {                                                 \
      fprintf(stderr, "Expected an int but got an error.\n");                  \
    }                                                                          \
    ASSERT(AST_is_integer(__tmp));                                             \
    ASSERT_EQ(AST_get_integer(__tmp), val);                                    \
  } while (0);

#define ASSERT_IS_SYM_EQ(node, cstr)                                           \
  do {                                                                         \
    ASTNode *__tmp = node;                                                     \
    if (AST_is_error(__tmp)) {                                                 \
      fprintf(stderr, "Expected a symbol but got an error.\n");                \
    }                                                                          \
    ASSERT(AST_is_symbol(__tmp));                                              \
    ASSERT_STR_EQ(AST_symbol_cstr(__tmp), cstr);                               \
  } while (0);

TEST read_with_integer_returns_integer(void) {
  char *input = "1234";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_INT_EQ(node, 1234);
  AST_heap_free(node);
  PASS();
}

TEST read_with_negative_integer_returns_integer(void) {
  char *input = "-1234";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_INT_EQ(node, -1234);
  AST_heap_free(node);
  PASS();
}

TEST read_with_positive_integer_returns_integer(void) {
  char *input = "+1234";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_INT_EQ(node, 1234);
  AST_heap_free(node);
  PASS();
}

TEST read_with_leading_whitespace_ignores_whitespace(void) {
  char *input = "   \t   \n  1234";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_INT_EQ(node, 1234);
  AST_heap_free(node);
  PASS();
}

TEST read_with_symbol_returns_symbol(void) {
  char *input = "hello?+-*=>";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_SYM_EQ(node, "hello?+-*=>");
  AST_heap_free(node);
  PASS();
}

TEST read_with_symbol_with_trailing_digits(void) {
  char *input = "add1 1";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_SYM_EQ(node, "add1");
  AST_heap_free(node);
  PASS();
}

TEST read_with_char_returns_char(void) {
  char *input = "'a'";
  ASTNode *node = Reader_read(input);
  ASSERT_IS_CHAR_EQ(node, 'a');
  ASSERT(AST_is_error(Reader_read("''")));
  ASSERT(AST_is_error(Reader_read("'aa'")));
  ASSERT(AST_is_error(Reader_read("'aa")));
  AST_heap_free(node);
  PASS();
}

TEST read_with_bool_returns_bool(void) {
  ASSERT_EQ(Reader_read("#t"), AST_new_bool(true));
  ASSERT_EQ(Reader_read("#f"), AST_new_bool(false));
  ASSERT(AST_is_error(Reader_read("#")));
  ASSERT(AST_is_error(Reader_read("#x")));
  ASSERT(AST_is_error(Reader_read("##")));
  PASS();
}

TEST read_with_nil_returns_nil(void) {
  char *input = "()";
  ASTNode *node = Reader_read(input);
  ASSERT(AST_is_nil(node));
  AST_heap_free(node);
  PASS();
}

TEST read_with_list_returns_list(void) {
  char *input = "( 1 2 0 )";
  ASTNode *node = Reader_read(input);
  ASSERT(AST_is_pair(node));
  ASSERT_IS_INT_EQ(AST_pair_car(node), 1);
  ASSERT_IS_INT_EQ(AST_pair_car(AST_pair_cdr(node)), 2);
  ASSERT_IS_INT_EQ(AST_pair_car(AST_pair_cdr(AST_pair_cdr(node))), 0);
  ASSERT(AST_is_nil(AST_pair_cdr(AST_pair_cdr(AST_pair_cdr(node)))));
  AST_heap_free(node);
  PASS();
}

TEST read_with_nested_list_returns_list(void) {
  char *input = "((hello world) (foo bar))";
  ASTNode *node = Reader_read(input);
  ASSERT(AST_is_pair(node));
  ASTNode *first = AST_pair_car(node);
  ASSERT(AST_is_pair(first));
  ASSERT_IS_SYM_EQ(AST_pair_car(first), "hello");
  ASSERT_IS_SYM_EQ(AST_pair_car(AST_pair_cdr(first)), "world");
  ASSERT(AST_is_nil(AST_pair_cdr(AST_pair_cdr(first))));
  ASTNode *second = AST_pair_car(AST_pair_cdr(node));
  ASSERT(AST_is_pair(second));
  ASSERT_IS_SYM_EQ(AST_pair_car(second), "foo");
  ASSERT_IS_SYM_EQ(AST_pair_car(AST_pair_cdr(second)), "bar");
  ASSERT(AST_is_nil(AST_pair_cdr(AST_pair_cdr(second))));
  AST_heap_free(node);
  PASS();
}

TEST buffer_write8_increases_length(Buffer *buf) {
  ASSERT_EQ(Buffer_len(buf), 0);
  Buffer_write8(buf, 0xdb);
  ASSERT_EQ(Buffer_at8(buf, 0), 0xdb);
  ASSERT_EQ(Buffer_len(buf), 1);
  PASS();
}

TEST buffer_write8_expands_buffer(void) {
  Buffer buf;
  Buffer_init(&buf, 1);
  ASSERT_EQ(buf.capacity, 1);
  ASSERT_EQ(buf.len, 0);
  Buffer_write8(&buf, 0xdb);
  Buffer_write8(&buf, 0xef);
  ASSERT(buf.capacity > 1);
  ASSERT_EQ(buf.len, 2);
  Buffer_deinit(&buf);
  PASS();
}

TEST buffer_write32_expands_buffer(void) {
  Buffer buf;
  Buffer_init(&buf, 1);
  ASSERT_EQ(buf.capacity, 1);
  ASSERT_EQ(buf.len, 0);
  Buffer_write32(&buf, 0xdeadbeef);
  ASSERT(buf.capacity > 1);
  ASSERT_EQ(buf.len, 4);
  Buffer_deinit(&buf);
  PASS();
}

TEST buffer_write32_writes_little_endian(Buffer *buf) {
  Buffer_write32(buf, 0xdeadbeef);
  ASSERT_EQ(Buffer_at8(buf, 0), 0xef);
  ASSERT_EQ(Buffer_at8(buf, 1), 0xbe);
  ASSERT_EQ(Buffer_at8(buf, 2), 0xad);
  ASSERT_EQ(Buffer_at8(buf, 3), 0xde);
  PASS();
}

TEST compile_positive_integer(Buffer *buf) {
  word value = 123;
  ASTNode *node = AST_new_integer(value);
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm(123)
  byte expected[] = {0x48, 0xc7, 0xc0, 0xec, 0x01, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(value));
  PASS();
}

TEST compile_negative_integer(Buffer *buf) {
  word value = -123;
  ASTNode *node = AST_new_integer(value);
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm(-123)
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0xfe, 0xff, 0xff};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(value));
  PASS();
}

TEST compile_char(Buffer *buf) {
  char value = 'a';
  ASTNode *node = AST_new_char(value);
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm('a')
  byte expected[] = {0x48, 0xc7, 0xc0, 0x0f, 0x61, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_char(value));
  PASS();
}

TEST compile_true(Buffer *buf) {
  ASTNode *node = AST_new_bool(true);
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm(true)
  byte expected[] = {0x48, 0xc7, 0xc0, 0x9f, 0x0, 0x0, 0x0};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  PASS();
}

TEST compile_false(Buffer *buf) {
  ASTNode *node = AST_new_bool(false);
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm(false)
  byte expected[] = {0x48, 0xc7, 0xc0, 0x1f, 0x00, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  PASS();
}

TEST compile_nil(Buffer *buf) {
  ASTNode *node = AST_nil();
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov eax, imm(nil)
  byte expected[] = {0x48, 0xc7, 0xc0, 0x2f, 0x00, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_nil());
  PASS();
}

TEST compile_unary_add1(Buffer *buf) {
  ASTNode *node = new_unary_call("add1", AST_new_integer(123));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov rax, imm(123); add rax, imm(1)
  byte expected[] = {0x48, 0xc7, 0xc0, 0xec, 0x01, 0x00, 0x00,
                     0x48, 0x05, 0x04, 0x00, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(124));
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_add1_nested(Buffer *buf) {
  ASTNode *node =
      new_unary_call("add1", new_unary_call("add1", AST_new_integer(123)));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov rax, imm(123); add rax, imm(1); add rax, imm(1)
  byte expected[] = {0x48, 0xc7, 0xc0, 0xec, 0x01, 0x00, 0x00, 0x48, 0x05, 0x04,
                     0x00, 0x00, 0x00, 0x48, 0x05, 0x04, 0x00, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(125));
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_sub1(Buffer *buf) {
  ASTNode *node = new_unary_call("sub1", AST_new_integer(123));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov rax, imm(123); sub rax, imm(1)
  byte expected[] = {0x48, 0xc7, 0xc0, 0xec, 0x01, 0x00, 0x00,
                     0x48, 0x2d, 0x04, 0x00, 0x00, 0x00};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(122));
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_integer_to_char(Buffer *buf) {
  ASTNode *node = new_unary_call("integer->char", AST_new_integer(97));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov rax, imm(97); shl rax, 6; or rax, 0xf
  byte expected[] = {0x48, 0xc7, 0xc0, 0x84, 0x01, 0x00, 0x00, 0x48,
                     0xc1, 0xe0, 0x06, 0x48, 0x83, 0xc8, 0x0f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_char('a'));
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_char_to_integer(Buffer *buf) {
  ASTNode *node = new_unary_call("char->integer", AST_new_char('a'));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // mov rax, imm('a'); shr rax, 6
  byte expected[] = {0x48, 0xc7, 0xc0, 0x0f, 0x61, 0x00,
                     0x00, 0x48, 0xc1, 0xe8, 0x06};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(97));
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_nilp_with_nil_returns_true(Buffer *buf) {
  ASTNode *node = new_unary_call("nil?", AST_nil());
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 2f 00 00 00    mov    rax,0x2f
  // 7:  48 3d 2f 00 00 00       cmp    rax,0x0000002f
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x2f, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x2f, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_nilp_with_non_nil_returns_false(Buffer *buf) {
  ASTNode *node = new_unary_call("nil?", AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 14 00 00 00    mov    rax,0x14
  // 7:  48 3d 2f 00 00 00       cmp    rax,0x0000002f
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x2f, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_zerop_with_zero_returns_true(Buffer *buf) {
  ASTNode *node = new_unary_call("zero?", AST_new_integer(0));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 7:  48 3d 00 00 00 00       cmp    rax,0x00000000
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_zerop_with_non_zero_returns_false(Buffer *buf) {
  ASTNode *node = new_unary_call("zero?", AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 14 00 00 00    mov    rax,0x14
  // 7:  48 3d 00 00 00 00       cmp    rax,0x00000000
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_not_with_false_returns_true(Buffer *buf) {
  ASTNode *node = new_unary_call("not", AST_new_bool(false));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 1f 00 00 00    mov    rax,0x1f
  // 7:  48 3d 1f 00 00 00       cmp    rax,0x0000001f
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x1f, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x1f, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_not_with_non_false_returns_false(Buffer *buf) {
  ASTNode *node = new_unary_call("not", AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 14 00 00 00    mov    rax,0x14
  // 7:  48 3d 1f 00 00 00       cmp    rax,0x0000001f
  // d:  48 c7 c0 00 00 00 00    mov    rax,0x0
  // 14: 0f 94 c0                sete   al
  // 17: 48 c1 e0 07             shl    rax,0x7
  // 1b: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x48,
                     0x3d, 0x1f, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0,
                     0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x48,
                     0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_integerp_with_integer_returns_true(Buffer *buf) {
  ASTNode *node = new_unary_call("integer?", AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 14 00 00 00    mov    rax,0x14
  // 7:  48 83 e0 03             and    rax,0x3
  // b:  48 3d 00 00 00 00       cmp    rax,0x00000000
  // 11: 48 c7 c0 00 00 00 00    mov    rax,0x0
  // 18: 0f 94 c0                sete   al
  // 1b: 48 c1 e0 07             shl    rax,0x7
  // 1f: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x48, 0x83,
                     0xe0, 0x03, 0x48, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48,
                     0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0,
                     0x48, 0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_integerp_with_non_integer_returns_false(Buffer *buf) {
  ASTNode *node = new_unary_call("integer?", AST_nil());
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 2f 00 00 00    mov    rax,0x2f
  // 7:  48 83 e0 03             and    rax,0x3
  // b:  48 3d 00 00 00 00       cmp    rax,0x00000000
  // 11: 48 c7 c0 00 00 00 00    mov    rax,0x0
  // 18: 0f 94 c0                sete   al
  // 1b: 48 c1 e0 07             shl    rax,0x7
  // 1f: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x2f, 0x00, 0x00, 0x00, 0x48, 0x83,
                     0xe0, 0x03, 0x48, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48,
                     0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0,
                     0x48, 0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_booleanp_with_boolean_returns_true(Buffer *buf) {
  ASTNode *node = new_unary_call("boolean?", AST_new_bool(true));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 9f 00 00 00    mov    rax,0x9f
  // 7:  48 83 e0 3f             and    rax,0x3f
  // b:  48 3d 1f 00 00 00       cmp    rax,0x0000001f
  // 11: 48 c7 c0 00 00 00 00    mov    rax,0x0
  // 18: 0f 94 c0                sete   al
  // 1b: 48 c1 e0 07             shl    rax,0x7
  // 1f: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x9f, 0x00, 0x00, 0x00, 0x48, 0x83,
                     0xe0, 0x3f, 0x48, 0x3d, 0x1f, 0x00, 0x00, 0x00, 0x48,
                     0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0,
                     0x48, 0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_true());
  AST_heap_free(node);
  PASS();
}

TEST compile_unary_booleanp_with_non_boolean_returns_false(Buffer *buf) {
  ASTNode *node = new_unary_call("boolean?", AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // 0:  48 c7 c0 14 00 00 00    mov    rax,0x14
  // 7:  48 83 e0 3f             and    rax,0x3f
  // b:  48 3d 1f 00 00 00       cmp    rax,0x0000001f
  // 11: 48 c7 c0 00 00 00 00    mov    rax,0x0
  // 18: 0f 94 c0                sete   al
  // 1b: 48 c1 e0 07             shl    rax,0x7
  // 1f: 48 83 c8 1f             or     rax,0x1f
  byte expected[] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x48, 0x83,
                     0xe0, 0x3f, 0x48, 0x3d, 0x1f, 0x00, 0x00, 0x00, 0x48,
                     0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x94, 0xc0,
                     0x48, 0xc1, 0xe0, 0x07, 0x48, 0x83, 0xc8, 0x1f};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_false());
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_plus(Buffer *buf) {
  ASTNode *node = new_binary_call("+", AST_new_integer(5), AST_new_integer(8));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // 0:  48 c7 c0 20 00 00 00    mov    rax,0x20
      0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,
      // 7:  48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // b:  48 c7 c0 14 00 00 00    mov    rax,0x14
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // 12: 48 03 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x03, 0x44, 0x24, 0xf8};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(13));
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_plus_nested(Buffer *buf) {
  ASTNode *node = new_binary_call(
      "+", new_binary_call("+", AST_new_integer(1), AST_new_integer(2)),
      new_binary_call("+", AST_new_integer(3), AST_new_integer(4)));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // 4:  48 c7 c0 10 00 00 00    mov    rax,0x10
      0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,
      // b:  48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // f:  48 c7 c0 0c 00 00 00    mov    rax,0xc
      0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00,
      // 16: 48 03 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x03, 0x44, 0x24, 0xf8,
      // 1a: 48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // 1e: 48 c7 c0 08 00 00 00    mov    rax,0x8
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
      // 25: 48 89 45 f0             mov    QWORD PTR [rsp-0x10],rax
      0x48, 0x89, 0x44, 0x24, 0xf0,
      // 29: 48 c7 c0 04 00 00 00    mov    rax,0x4
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // 30: 48 03 45 f0             add    rax,QWORD PTR [rsp-0x10]
      0x48, 0x03, 0x44, 0x24, 0xf0,
      // 34: 48 03 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x03, 0x44, 0x24, 0xf8};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(10));
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_minus(Buffer *buf) {
  ASTNode *node = new_binary_call("-", AST_new_integer(5), AST_new_integer(8));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // 0:  48 c7 c0 20 00 00 00    mov    rax,0x20
      0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,
      // 7:  48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // b:  48 c7 c0 14 00 00 00    mov    rax,0x14
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // 12: 48 2b 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x2b, 0x44, 0x24, 0xf8};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(-3));
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_minus_nested(Buffer *buf) {
  ASTNode *node = new_binary_call(
      "-", new_binary_call("-", AST_new_integer(5), AST_new_integer(1)),
      new_binary_call("-", AST_new_integer(4), AST_new_integer(3)));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // 4:  48 c7 c0 0c 00 00 00    mov    rax,0xc
      0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00,
      // b:  48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // f:  48 c7 c0 10 00 00 00    mov    rax,0x10
      0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,
      // 16: 48 2b 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x2b, 0x44, 0x24, 0xf8,
      // 1a: 48 89 45 f8             mov    QWORD PTR [rsp-0x8],rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // 1e: 48 c7 c0 04 00 00 00    mov    rax,0x4
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // 25: 48 89 45 f0             mov    QWORD PTR [rsp-0x10],rax
      0x48, 0x89, 0x44, 0x24, 0xf0,
      // 29: 48 c7 c0 14 00 00 00    mov    rax,0x14
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // 30: 48 2b 45 f0             add    rax,QWORD PTR [rsp-0x10]
      0x48, 0x2b, 0x44, 0x24, 0xf0,
      // 34: 48 2b 45 f8             add    rax,QWORD PTR [rsp-0x8]
      0x48, 0x2b, 0x44, 0x24, 0xf8};
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ(result, Object_encode_integer(3));
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_mul(Buffer *buf) {
  ASTNode *node = new_binary_call("*", AST_new_integer(5), AST_new_integer(8));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(40), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_mul_nested(Buffer *buf) {
  ASTNode *node = new_binary_call(
      "*", new_binary_call("*", AST_new_integer(1), AST_new_integer(2)),
      new_binary_call("*", AST_new_integer(3), AST_new_integer(4)));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(24), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_eq_with_same_address_returns_true(Buffer *buf) {
  ASTNode *node = new_binary_call("=", AST_new_integer(5), AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_true(), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_eq_with_different_address_returns_false(Buffer *buf) {
  ASTNode *node = new_binary_call("=", AST_new_integer(5), AST_new_integer(4));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_false(), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_lt_with_left_less_than_right_returns_true(Buffer *buf) {
  ASTNode *node = new_binary_call("<", AST_new_integer(-5), AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_true(), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_lt_with_left_equal_to_right_returns_false(Buffer *buf) {
  ASTNode *node = new_binary_call("<", AST_new_integer(5), AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_false(), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_binary_lt_with_left_greater_than_right_returns_false(Buffer *buf) {
  ASTNode *node = new_binary_call("<", AST_new_integer(6), AST_new_integer(5));
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_false(), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_symbol_in_env_returns_value(Buffer *buf) {
  ASTNode *node = AST_new_symbol("hello");
  Env env0 = Env_bind("hello", -33, /*prev=*/NULL);
  Env env1 = Env_bind("world", -66, &env0);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, &env1, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {// mov rax, [rsp-33]
                     0x48, 0x8b, 0x44, 0x24, 0x100 - 33};
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_symbol_in_closure_returns_value(Buffer *buf) {
  ASTNode *node = AST_new_symbol("hello");
  Env env0 = Env_bind("hello", 33, /*prev=*/NULL);
  Env env1 = Env_bind("world", 66, &env0);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, &env1, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {// mov rax, [Closure+33]
                     0x48, 0x8b, 0x47, 33};
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_symbol_in_env_returns_first_value(Buffer *buf) {
  ASTNode *node = AST_new_symbol("hello");
  Env env0 = Env_bind("hello", -55, /*prev=*/NULL);
  Env env1 = Env_bind("hello", -66, &env0);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, &env1, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {// mov rax, [rsp-66]
                     0x48, 0x8b, 0x44, 0x24, 0x100 - 66};
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_symbol_not_in_env_raises_compile_error(Buffer *buf) {
  ASTNode *node = AST_new_symbol("hello");
  int compile_result =
      Compile_expr(buf, node, -kWordSize, /*varenv=*/NULL, /*labels=*/NULL);
  ASSERT_EQ(compile_result, -1);
  AST_heap_free(node);
  PASS();
}

TEST compile_let_with_no_bindings(Buffer *buf) {
  ASTNode *node = Reader_read("(let () (+ 1 2))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(3), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_let_with_one_binding(Buffer *buf) {
  ASTNode *node = Reader_read("(let ((a 1)) (+ a 2))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(3), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_let_with_multiple_bindings(Buffer *buf) {
  ASTNode *node = Reader_read("(let ((a 1) (b 2)) (+ a b))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(3), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_nested_let(Buffer *buf) {
  ASTNode *node = Reader_read("(let ((a 1)) (let ((b 2)) (+ a b)))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(3), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_let_is_not_let_star(Buffer *buf) {
  ASTNode *node = Reader_read("(let ((a 1) (b a)) a)");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, -1);
  AST_heap_free(node);
  PASS();
}

TEST compile_if_with_true_cond(Buffer *buf) {
  ASTNode *node = Reader_read("(if #t 1 2)");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // mov rax, 0x9f
      0x48, 0xc7, 0xc0, 0x9f, 0x00, 0x00, 0x00,
      // cmp rax, 0x1f
      0x48, 0x3d, 0x1f, 0x00, 0x00, 0x00,
      // je alternate
      0x0f, 0x84, 0x0c, 0x00, 0x00, 0x00,
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // jmp end
      0xe9, 0x07, 0x00, 0x00, 0x00,
      // alternate:
      // mov rax, compile(2)
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00
      // end:
  };
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_if_with_false_cond(Buffer *buf) {
  ASTNode *node = Reader_read("(if #f 1 2)");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  byte expected[] = {
      // mov rax, 0x1f
      0x48, 0xc7, 0xc0, 0x1f, 0x00, 0x00, 0x00,
      // cmp rax, 0x1f
      0x48, 0x3d, 0x1f, 0x00, 0x00, 0x00,
      // je alternate
      0x0f, 0x84, 0x0c, 0x00, 0x00, 0x00,
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // jmp end
      0xe9, 0x07, 0x00, 0x00, 0x00,
      // alternate:
      // mov rax, compile(2)
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00
      // end:
  };
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(2), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_nested_if(Buffer *buf) {
  ASTNode *node = Reader_read("(if (< 1 2) (if #f 3 4) 5)");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(4), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_cons(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(cons 1 2)");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, 0x4
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
      // mov [Heap+Cdr], rax
      0x48, 0x89, 0x46, 0x08,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [Heap+Car], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, kPairTag
      0x48, 0x83, 0xc8, 0x01,
      // add Heap, 2*kWordSize
      0x48, 0x81, 0xc6, 0x10, 0x00, 0x00, 0x00,
  };
  // clang-format on
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_pair(result));
  ASSERT_EQ_FMT(Object_encode_integer(1), Object_pair_car(result), "0x%lx");
  ASSERT_EQ_FMT(Object_encode_integer(2), Object_pair_cdr(result), "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_two_cons(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read(
      "(let ((a (cons 1 2)) (b (cons 3 4))) (cons (cdr a) (cdr b)))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_pair(result));
  ASSERT_EQ_FMT(Object_encode_integer(2), Object_pair_car(result), "0x%lx");
  ASSERT_EQ_FMT(Object_encode_integer(4), Object_pair_cdr(result), "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_nested_cons(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(cons (cons 1 2) (cons 3 4))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_pair(result));
  ASSERT(Object_is_pair(Object_pair_car(result)));
  ASSERT_EQ_FMT(Object_encode_integer(1),
                Object_pair_car(Object_pair_car(result)), "0x%lx");
  ASSERT_EQ_FMT(Object_encode_integer(2),
                Object_pair_cdr(Object_pair_car(result)), "0x%lx");
  ASSERT(Object_is_pair(Object_pair_cdr(result)));
  ASSERT_EQ_FMT(Object_encode_integer(3),
                Object_pair_car(Object_pair_cdr(result)), "0x%lx");
  ASSERT_EQ_FMT(Object_encode_integer(4),
                Object_pair_cdr(Object_pair_cdr(result)), "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_car(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(car (cons 1 2))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, 0x4
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
      // mov [Heap+Cdr], rax
      0x48, 0x89, 0x46, 0x08,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [Heap+Car], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, kPairTag
      0x48, 0x83, 0xc8, 0x01,
      // add Heap, 2*kWordSize
      0x48, 0x81, 0xc6, 0x10, 0x00, 0x00, 0x00,
      // mov rax, [rax-1]
      0x48, 0x8b, 0x40, 0xff,
  };
  // clang-format on
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_cdr(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(cdr (cons 1 2))");
  int compile_result = Testing_compile_expr_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, 0x4
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
      // mov [Heap+Cdr], rax
      0x48, 0x89, 0x46, 0x08,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [Heap+Car], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, kPairTag
      0x48, 0x83, 0xc8, 0x01,
      // add Heap, 2*kWordSize
      0x48, 0x81, 0xc6, 0x10, 0x00, 0x00, 0x00,
      // mov rax, [rax+7]
      0x48, 0x8b, 0x40, 0x07,
  };
  // clang-format on
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(2), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_no_params(Buffer *buf) {
  ASTNode *node = Reader_read("(code () () 1)");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_expr(buf);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_one_param(Buffer *buf) {
  ASTNode *node = Reader_read("(code (x) () x)");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_one_freevar(Buffer *buf) {
  ASTNode *node = Reader_read("(code () (x) x)");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [Closure+8]
      0x48, 0x8b, 0x47, 0x08,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_two_params(Buffer *buf) {
  ASTNode *node = Reader_read("(code (x y) () (+ x y))");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [rsp-16]
      0x48, 0x8b, 0x44, 0x24, 0xf0,
      // mov [rsp-24], rax
      0x48, 0x89, 0x44, 0x24, 0xe8,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // add rax, [rsp-24]
      0x48, 0x03, 0x44, 0x24, 0xe8,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_two_freevars(Buffer *buf) {
  ASTNode *node = Reader_read("(code () (x y) (+ x y))");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [Closure+16]
      0x48, 0x8b, 0x47, 0x10,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, [Closure+8]
      0x48, 0x8b, 0x47, 0x08,
      // add rax, [rsp-8]
      0x48, 0x03, 0x44, 0x24, 0xf8,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_code_with_params_and_freevars(Buffer *buf) {
  ASTNode *node = Reader_read("(code (x) (y) (+ x y))");
  int compile_result = Compile_code(buf, node, /*labels=*/NULL);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [Closure+8]
      0x48, 0x8b, 0x47, 0x08,
      // mov [rsp-16], rax
      0x48, 0x89, 0x44, 0x24, 0xf0,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // add rax, [rsp-16]
      0x48, 0x03, 0x44, 0x24, 0xf0,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  AST_heap_free(node);
  PASS();
}

TEST compile_labels_with_no_labels(Buffer *buf) {
  ASTNode *node = Reader_read("(labels () 1)");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, /*heap=*/NULL);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_labels_with_one_label(Buffer *buf) {
  ASTNode *node = Reader_read("(labels ((const (code () () 5))) 1)");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // ret
      0xc3,
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, 0x2
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, /*heap=*/NULL);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_funcall_with_no_params(Buffer *buf, uword *heap) {
  ASTNode *node =
      Reader_read("(labels ((const (code () () 5))) ((closure const)))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // ret
      0xc3,
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0  (code offset)
      0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-8], rdi  save closure
      0x48, 0x89, 0x7c, 0x24, 0xf8,
      // mov rdi, rax
      0x48, 0x89, 0xc7,
      // sub rdi, 0x6
      0x48, 0x81, 0xef, 0x06, 0x00, 0x00, 0x00,
      // mov rax, [Closure]   closure[label]
      0x48, 0x8b, 0x47, 0x00,
      // sub rsp, 8
      0x48, 0x81, 0xec, 0x08, 0x00, 0x00, 0x00,
      // call near rax (const)
      0xff, 0xd0,
      // add rsp, 8
      0x48, 0x81, 0xc4, 0x08, 0x00, 0x00, 0x00,
      // mov rdi, [rsp-8]  reload closure
      0x48, 0x8b, 0x7c, 0x24, 0xf8,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(5), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_funcall_with_no_params_and_locals(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read(
      "(labels ((const (code () () 5))) (let ((a 1)) ((closure const))))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // ret
      0xc3,
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0  (code offset)
      0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-16], rdi  save closure
      0x48, 0x89, 0x7c, 0x24, 0xf0,
      // mov rdi, rax
      0x48, 0x89, 0xc7,
      // sub rdi, 0x6
      0x48, 0x81, 0xef, 0x06, 0x00, 0x00, 0x00,
      // mov rax, [Closure]   closure[label]
      0x48, 0x8b, 0x47, 0x00,
      // sub rsp, 16
      0x48, 0x81, 0xec, 0x10, 0x00, 0x00, 0x00,
      // call near rax (const)
      0xff, 0xd0,
      // add rsp, 16
      0x48, 0x81, 0xc4, 0x10, 0x00, 0x00, 0x00,
      // mov rdi, [rsp-16]  reload closure
      0x48, 0x8b, 0x7c, 0x24, 0xf0,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(5), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_funcall_with_one_param(Buffer *buf, uword *heap) {
  ASTNode *node =
      Reader_read("(labels ((id (code (x) () x))) ((closure id) 5))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // ret
      0xc3,
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // mov [rsp-24], rax
      0x48, 0x89, 0x44, 0x24, 0xe8,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0  (code offset)
      0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-8], rdi  save closure
      0x48, 0x89, 0x7c, 0x24, 0xf8,
      // mov rdi, rax
      0x48, 0x89, 0xc7,
      // sub rdi, 0x6
      0x48, 0x81, 0xef, 0x06, 0x00, 0x00, 0x00,
      // mov rax, [Closure]   closure[label]
      0x48, 0x8b, 0x47, 0x00,
      // sub rsp, 8
      0x48, 0x81, 0xec, 0x08, 0x00, 0x00, 0x00,
      // call near rax (const)
      0xff, 0xd0,
      // add rsp, 8
      0x48, 0x81, 0xc4, 0x08, 0x00, 0x00, 0x00,
      // mov rdi, [rsp-8]  reload closure
      0x48, 0x8b, 0x7c, 0x24, 0xf8,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(5), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

SUITE(object_tests) {
  RUN_TEST(encode_positive_integer);
  RUN_TEST(encode_negative_integer);
  RUN_TEST(encode_char);
  RUN_TEST(decode_char);
  RUN_TEST(encode_bool);
  RUN_TEST(decode_bool);
  RUN_TEST(address);
}

TEST compile_funcall_with_one_param_and_locals(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read(
      "(labels ((id (code (x) () x))) (let ((a 1)) ((closure id) 5)))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // ret
      0xc3,
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // mov [rsp-32], rax
      0x48, 0x89, 0x44, 0x24, 0xe0,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0  (code offset)
      0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-16], rdi  save closure
      0x48, 0x89, 0x7c, 0x24, 0xf0,
      // mov rdi, rax
      0x48, 0x89, 0xc7,
      // sub rdi, 0x6
      0x48, 0x81, 0xef, 0x06, 0x00, 0x00, 0x00,
      // mov rax, [Closure]   closure[label]
      0x48, 0x8b, 0x47, 0x00,
      // sub rsp, 16
      0x48, 0x81, 0xec, 0x10, 0x00, 0x00, 0x00,
      // call near rax (const)
      0xff, 0xd0,
      // add rsp, 16
      0x48, 0x81, 0xc4, 0x10, 0x00, 0x00, 0x00,
      // mov rdi, [rsp-16]  reload closure
      0x48, 0x8b, 0x7c, 0x24, 0xf0,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(5), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_funcall_with_two_params_and_locals(Buffer *buf, uword *heap) {
  ASTNode *node =
      Reader_read("(labels ((add (code (x y) () (+ x y)))) (let ((a "
                  "1)) ((closure add) 5 a)))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  // clang-format off
  byte expected[] = {
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf0,
      // mov [rsp-24], rax
      0x48, 0x89, 0x44, 0x24, 0xe8,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // add rax, [rsp-24]
      0x48, 0x03, 0x44, 0x24, 0xe8,
      // ret
      0xc3,

      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, compile(5)
      0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
      // mov [rsp-32], rax
      0x48, 0x89, 0x44, 0x24, 0xe0,
      // mov rax, [rsp-8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [rsp-40], rax
      0x48, 0x89, 0x44, 0x24, 0xd8,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0  (code offset)
      0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-16], rdi  save closure
      0x48, 0x89, 0x7c, 0x24, 0xf0,
      // mov rdi, rax
      0x48, 0x89, 0xc7,
      // sub rdi, 0x6
      0x48, 0x81, 0xef, 0x06, 0x00, 0x00, 0x00,
      // mov rax, [Closure]   closure[label]
      0x48, 0x8b, 0x47, 0x00,
      // sub rsp, 16
      0x48, 0x81, 0xec, 0x10, 0x00, 0x00, 0x00,
      // call near rax (const)
      0xff, 0xd0,
      // add rsp, 16
      0x48, 0x81, 0xc4, 0x10, 0x00, 0x00, 0x00,
      // mov rdi, [rsp-16]  reload closure
      0x48, 0x8b, 0x7c, 0x24, 0xf0,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(6), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_nested_funcall(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(labels ((add (code (x y) () (+ x y)))"
                              "         (sub (code (x y) () (- x y))))"
                              "    ((closure sub) 4 ((closure add) 1 2)))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(1), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_multilevel_funcall(Buffer *buf, uword *heap) {
  ASTNode *node =
      Reader_read("(labels ((add (code (x y) () (+ x y)))"
                  "         (add2 (code (x y) () ((closure add) x y))))"
                  "    ((closure add2) 1 2))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(3), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_factorial_funcall(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read(
      "(labels ((factorial (code (x) ()"
      "            (if (< x 2) 1 (* x ((closure factorial) (- x 1)))))))"
      "    ((closure factorial) 5))");
  int compile_result = Compile_entry(buf, node);
  ASSERT_EQ(compile_result, 0);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT_EQ_FMT(Object_encode_integer(120), result, "0x%lx");
  AST_heap_free(node);
  PASS();
}

TEST compile_closure_undefined_label(Buffer *buf) {
  ASTNode *node = Reader_read("(closure nonexistent)");
  int compile_result =
      Compile_expr(buf, node, -kWordSize, /*varenv=*/NULL, /*labels=*/NULL);
  ASSERT_EQ(compile_result, -1);
  AST_heap_free(node);
  PASS();
}

TEST compile_closure_no_freevars(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(closure foo)");
  uword closure_ptr = 0xe3;
  Env labels = Env_bind("foo", closure_ptr, NULL);
  Buffer_write_arr(buf, kEntryPrologue, sizeof kEntryPrologue);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, /*varenv=*/NULL, &labels);
  ASSERT_EQ(compile_result, 0);
  Emit_ret(buf);
  // clang-format off
  byte expected[] = {
      // mov Code, rsi
      0x48, 0x8b, 0xce,
      // mov Heap, rdi
      0x48, 0x89, 0xfe,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0xe3  (code offset)
      0x48, 0x05, 0xe3, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x8 (label + 0 freevars)
      0x48, 0x81, 0xc6, 0x08, 0x00, 0x00, 0x00,
      // ret
      0xc3,
  };
  // clang-format on
  EXPECT_EQUALS_BYTES(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_closure(result));
  ASSERT_EQ_FMT((uword)(buf->address + closure_ptr),
                Object_closure_label(result), "%ld");
  AST_heap_free(node);
  PASS();
}

TEST compile_closure_one_freevar(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(closure foo 1)");
  uword closure_ptr = 0xe3;
  Env labels = Env_bind("foo", closure_ptr, NULL);
  Buffer_write_arr(buf, kEntryPrologue, sizeof kEntryPrologue);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, /*varenv=*/NULL, &labels);
  ASSERT_EQ(compile_result, 0);
  Emit_ret(buf);
  // clang-format off
  byte expected[] = {
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, [rsp - 8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [Heap + 8], rax
      0x48, 0x89, 0x46, 0x08,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0xe3  (code offset)
      0x48, 0x05, 0xe3, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x10 (label + 1 freevar)
      0x48, 0x81, 0xc6, 0x10, 0x00, 0x00, 0x00,
  };
  // clang-format on
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_closure(result));
  ASSERT_EQ_FMT((uword)(buf->address + closure_ptr),
                Object_closure_label(result), "%ld");
  ASSERT_EQ_FMT(Object_encode_integer(1), Object_closure_freevar(result, 0),
                "%ld");
  AST_heap_free(node);
  PASS();
}

TEST compile_closure_two_freevars(Buffer *buf, uword *heap) {
  ASTNode *node = Reader_read("(closure foo 1 2)");
  uword closure_ptr = 0xe3;
  Env labels = Env_bind("foo", closure_ptr, NULL);
  Buffer_write_arr(buf, kEntryPrologue, sizeof kEntryPrologue);
  int compile_result =
      Compile_expr(buf, node, -kWordSize, /*varenv=*/NULL, &labels);
  ASSERT_EQ(compile_result, 0);
  Emit_ret(buf);
  // clang-format off
  byte expected[] = {
      // mov rax, compile(1)
      0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
      // mov [rsp-8], rax
      0x48, 0x89, 0x44, 0x24, 0xf8,
      // mov rax, compile(2)
      0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
      // mov [rsp-16], rax
      0x48, 0x89, 0x44, 0x24, 0xf0,
      // mov rax, [rsp - 16]
      0x48, 0x8b, 0x44, 0x24, 0xf0,
      // mov [Heap + 16], rax
      0x48, 0x89, 0x46, 0x10,
      // mov rax, [rsp - 8]
      0x48, 0x8b, 0x44, 0x24, 0xf8,
      // mov [Heap + 8], rax
      0x48, 0x89, 0x46, 0x08,
      // mov rax, Code
      0x48, 0x89, 0xc8,
      // add rax, 0xe3  (code offset)
      0x48, 0x05, 0xe3, 0x00, 0x00, 0x00,
      // mov qword [Heap], rax
      0x48, 0x89, 0x46, 0x00,
      // mov rax, Heap
      0x48, 0x89, 0xf0,
      // or rax, 6
      0x48, 0x83, 0xc8, 0x06,
      // add Heap, 0x18 (label + 2 freevars)
      0x48, 0x81, 0xc6, 0x18, 0x00, 0x00, 0x00,
  };
  // clang-format on
  EXPECT_ENTRY_CONTAINS_CODE(buf, expected);
  Buffer_make_executable(buf);
  uword result = Testing_execute_entry(buf, heap);
  ASSERT(Object_is_closure(result));
  ASSERT_EQ_FMT((uword)(buf->address + closure_ptr),
                Object_closure_label(result), "%ld");
  ASSERT_EQ_FMT(Object_encode_integer(1), Object_closure_freevar(result, 0),
                "%ld");
  ASSERT_EQ_FMT(Object_encode_integer(2), Object_closure_freevar(result, 1),
                "%ld");
  AST_heap_free(node);
  PASS();
}

SUITE(ast_tests) {
  RUN_TEST(ast_new_pair);
  RUN_TEST(ast_pair_car_returns_car);
  RUN_TEST(ast_pair_cdr_returns_cdr);
  RUN_TEST(ast_new_symbol);
}

SUITE(reader_tests) {
  RUN_TEST(read_with_integer_returns_integer);
  RUN_TEST(read_with_negative_integer_returns_integer);
  RUN_TEST(read_with_positive_integer_returns_integer);
  RUN_TEST(read_with_leading_whitespace_ignores_whitespace);
  RUN_TEST(read_with_symbol_returns_symbol);
  RUN_TEST(read_with_symbol_with_trailing_digits);
  RUN_TEST(read_with_nil_returns_nil);
  RUN_TEST(read_with_list_returns_list);
  RUN_TEST(read_with_nested_list_returns_list);
  RUN_TEST(read_with_char_returns_char);
  RUN_TEST(read_with_bool_returns_bool);
}

SUITE(buffer_tests) {
  RUN_BUFFER_TEST(buffer_write8_increases_length);
  RUN_TEST(buffer_write8_expands_buffer);
  RUN_TEST(buffer_write32_expands_buffer);
  RUN_BUFFER_TEST(buffer_write32_writes_little_endian);
  RUN_BUFFER_TEST(emit_mov_reg_imm32_emits_modrm);
  RUN_BUFFER_TEST(emit_store_reg_indirect_emits_modrm_sib);
}

TEST free_in_with_immediate_returns_nil() {
  ASSERT(AST_is_nil(free_in(AST_new_integer(5))));
  ASSERT(AST_is_nil(free_in(AST_new_char('a'))));
  ASSERT(AST_is_nil(free_in(AST_new_bool(true))));
  ASSERT(AST_is_nil(free_in(AST_nil())));
  PASS();
}

TEST is_list_with_names(ASTNode *list, word n, ...) {
  if (!AST_is_pair(list)) {
    FAILm("Not a list");
  }
  va_list vl;
  va_start(vl, n);
  for (word i = 0; i < n; i++) {
    if (AST_is_nil(list)) {
      FAILm("List smaller than expected");
    }
    ASTNode *elt = AST_pair_car(list);
    if (!AST_is_symbol(elt)) {
      FAILm("List had non-symbol element");
    }
    const char *expected = va_arg(vl, const char *);
    if (!AST_symbol_matches(elt, expected)) {
      FAILm("List element does not match expected");
    }
    list = AST_pair_cdr(list);
  }
  if (!AST_is_nil(list)) {
    abort();
    FAILm("List larger than expected");
  }
  PASS();
}

TEST free_in_with_symbol_returns_list() {
  {
    ASTNode *result = free_in(AST_new_symbol("foo"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  PASS();
}

TEST free_in_with_if() {
  {
    ASTNode *result = free_in(Reader_read("(if 1 2 3)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(if foo 2 3)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(if 1 foo 3)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(if 1 2 foo)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(if foo 2 bar)"));
    CHECK_CALL(is_list_with_names(result, 2, "foo", "bar"));
  }
  {
    ASTNode *result = free_in(Reader_read("(if foo 2 foo)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  PASS();
}

TEST free_in_with_let() {
  {
    ASTNode *result = free_in(Reader_read("(let () 1)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(let () foo)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(let ((foo 1)) 1)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(let ((foo 1) (bar 2)) foo)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(let ((foo foo)) foo)"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(let ((foo bar) (bar 3)) foo)"));
    CHECK_CALL(is_list_with_names(result, 1, "bar"));
  }
  {
    ASTNode *result =
        free_in(Reader_read("(let ((foo 1)) (let ((bar 2)) (+ foo bar)))"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result =
        free_in(Reader_read("(let ((foo 1)) (let ((baz 2)) (+ foo bar)))"));
    CHECK_CALL(is_list_with_names(result, 1, "bar"));
  }
  PASS();
}

TEST free_in_with_lambda() {
  {
    ASTNode *result = free_in(Reader_read("(lambda () 1)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(lambda () (+ foo 1))"));
    CHECK_CALL(is_list_with_names(result, 1, "foo"));
  }
  {
    ASTNode *result = free_in(Reader_read("(lambda (foo) 1)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(lambda (foo bar) foo)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(lambda (foo) foo)"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result = free_in(Reader_read("(lambda (foo) (+ foo bar))"));
    CHECK_CALL(is_list_with_names(result, 1, "bar"));
  }
  {
    ASTNode *result =
        free_in(Reader_read("(lambda (foo) (lambda (bar) (+ foo bar)))"));
    ASSERT(AST_is_nil(result));
  }
  {
    ASTNode *result =
        free_in(Reader_read("(lambda (foo) (lambda (baz) (+ foo bar)))"));
    CHECK_CALL(is_list_with_names(result, 1, "bar"));
  }
  PASS();
}

TEST is_lambda_with_freevars(ASTNode *node, word n, ...) {
  if (!is_tagged_with(node, "lambda")) {
    FAILm("Not a lambda");
  }
  ASTNode *args = AST_pair_cdr(node);
  ASTNode *freevars = operand2(args);
  if (AST_is_nil(freevars) != (n == 0)) {
    FAILm("Expected freevars to be nil only when n == 0");
  }
  if (!AST_is_pair(freevars)) {
    FAILm("Freevars is not a list");
  }
  va_list vl;
  va_start(vl, n);
  for (word i = 0; i < n; i++) {
    if (AST_is_nil(freevars)) {
      FAILm("Freevars smaller than expected");
    }
    ASTNode *elt = AST_pair_car(freevars);
    if (!AST_is_symbol(elt)) {
      FAILm("Freevars had non-symbol element");
    }
    const char *expected = va_arg(vl, const char *);
    if (!AST_symbol_matches(elt, expected)) {
      FAILm("Freevars element does not match expected");
    }
    freevars = AST_pair_cdr(freevars);
  }
  if (!AST_is_nil(freevars)) {
    abort();
    FAILm("Freevars larger than expected");
  }
  PASS();
}

TEST transform_lambda_adds_freevars() {
  {
    ASTNode *result = Transform_lambda(Reader_read("(lambda () a)"));
    CHECK_CALL(is_lambda_with_freevars(result, 1, "a"));
  }
  {
    ASTNode *result = Transform_lambda(Reader_read("(lambda () (+ a b))"));
    CHECK_CALL(is_lambda_with_freevars(result, 2, "a", "b"));
  }
  {
    ASTNode *result =
        Transform_lambda(Reader_read("(lambda (y) (lambda () (+ x y)))"));
    CHECK_CALL(is_lambda_with_freevars(result, 1, "x"));
  }
  PASS();
}

TEST transform_let() {
  {
    ASTNode *result = Transform(Reader_read("(let () (lambda () a))"));
    ASSERT(is_tagged_with(result, "let"));
    ASTNode *bindings = AST_pair_car(AST_pair_cdr(result));
    ASSERT(AST_is_nil(bindings));
    ASTNode *body = AST_pair_car(AST_pair_cdr(AST_pair_cdr(result)));
    CHECK_CALL(is_lambda_with_freevars(body, 1, "a"));
  }
  {
    ASTNode *result = Transform(Reader_read("(let ((a (lambda () a))) 1)"));
    ASSERT(is_tagged_with(result, "let"));
    ASTNode *bindings = AST_pair_car(AST_pair_cdr(result));
    ASSERT(AST_is_pair(bindings));
    ASTNode *binding = AST_pair_car(bindings);
    ASTNode *value = AST_pair_car(AST_pair_cdr(binding));
    CHECK_CALL(is_lambda_with_freevars(value, 1, "a"));
  }
  PASS();
}

TEST transform_arbitrary_call() {
  {
    ASTNode *result = Transform(Reader_read("((lambda () x) 1)"));
    ASTNode *lambda = AST_pair_car(result);
    CHECK_CALL(is_lambda_with_freevars(lambda, 1, "x"));
  }
  {
    ASTNode *result = Transform(Reader_read("(foo (lambda () x) 1)"));
    ASTNode *lambda = AST_pair_car(AST_pair_cdr(result));
    CHECK_CALL(is_lambda_with_freevars(lambda, 1, "x"));
  }
  PASS();
}

SUITE(transform_tests) {
  RUN_TEST(free_in_with_immediate_returns_nil);
  RUN_TEST(free_in_with_symbol_returns_list);
  RUN_TEST(free_in_with_if);
  RUN_TEST(free_in_with_let);
  RUN_TEST(free_in_with_lambda);
  RUN_TEST(transform_lambda_adds_freevars);
  RUN_TEST(transform_let);
  RUN_TEST(transform_arbitrary_call);
}

SUITE(compiler_tests) {
  RUN_BUFFER_TEST(compile_positive_integer);
  RUN_BUFFER_TEST(compile_negative_integer);
  RUN_BUFFER_TEST(compile_char);
  RUN_BUFFER_TEST(compile_true);
  RUN_BUFFER_TEST(compile_false);
  RUN_BUFFER_TEST(compile_nil);
  RUN_BUFFER_TEST(compile_unary_add1);
  RUN_BUFFER_TEST(compile_unary_add1_nested);
  RUN_BUFFER_TEST(compile_unary_sub1);
  RUN_BUFFER_TEST(compile_unary_integer_to_char);
  RUN_BUFFER_TEST(compile_unary_char_to_integer);
  RUN_BUFFER_TEST(compile_unary_nilp_with_nil_returns_true);
  RUN_BUFFER_TEST(compile_unary_nilp_with_non_nil_returns_false);
  RUN_BUFFER_TEST(compile_unary_zerop_with_zero_returns_true);
  RUN_BUFFER_TEST(compile_unary_zerop_with_non_zero_returns_false);
  RUN_BUFFER_TEST(compile_unary_not_with_false_returns_true);
  RUN_BUFFER_TEST(compile_unary_not_with_non_false_returns_false);
  RUN_BUFFER_TEST(compile_unary_integerp_with_integer_returns_true);
  RUN_BUFFER_TEST(compile_unary_integerp_with_non_integer_returns_false);
  RUN_BUFFER_TEST(compile_unary_booleanp_with_boolean_returns_true);
  RUN_BUFFER_TEST(compile_unary_booleanp_with_non_boolean_returns_false);
  RUN_BUFFER_TEST(compile_binary_plus);
  RUN_BUFFER_TEST(compile_binary_plus_nested);
  RUN_BUFFER_TEST(compile_binary_minus);
  RUN_BUFFER_TEST(compile_binary_minus_nested);
  RUN_BUFFER_TEST(compile_binary_mul);
  RUN_BUFFER_TEST(compile_binary_mul_nested);
  RUN_BUFFER_TEST(compile_binary_eq_with_same_address_returns_true);
  RUN_BUFFER_TEST(compile_binary_eq_with_different_address_returns_false);
  RUN_BUFFER_TEST(compile_binary_lt_with_left_less_than_right_returns_true);
  RUN_BUFFER_TEST(compile_binary_lt_with_left_equal_to_right_returns_false);
  RUN_BUFFER_TEST(compile_binary_lt_with_left_greater_than_right_returns_false);
  RUN_BUFFER_TEST(compile_symbol_in_env_returns_value);
  RUN_BUFFER_TEST(compile_symbol_in_closure_returns_value);
  RUN_BUFFER_TEST(compile_symbol_in_env_returns_first_value);
  RUN_BUFFER_TEST(compile_symbol_not_in_env_raises_compile_error);
  RUN_BUFFER_TEST(compile_let_with_no_bindings);
  RUN_BUFFER_TEST(compile_let_with_one_binding);
  RUN_BUFFER_TEST(compile_let_with_multiple_bindings);
  RUN_BUFFER_TEST(compile_nested_let);
  RUN_BUFFER_TEST(compile_let_is_not_let_star);
  RUN_BUFFER_TEST(compile_if_with_true_cond);
  RUN_BUFFER_TEST(compile_if_with_false_cond);
  RUN_BUFFER_TEST(compile_nested_if);
  RUN_HEAP_TEST(compile_cons);
  RUN_HEAP_TEST(compile_two_cons);
  RUN_HEAP_TEST(compile_nested_cons);
  RUN_HEAP_TEST(compile_car);
  RUN_HEAP_TEST(compile_cdr);
  RUN_BUFFER_TEST(compile_code_with_no_params);
  RUN_BUFFER_TEST(compile_code_with_one_param);
  RUN_BUFFER_TEST(compile_code_with_one_freevar);
  RUN_BUFFER_TEST(compile_code_with_two_params);
  RUN_BUFFER_TEST(compile_code_with_two_freevars);
  RUN_BUFFER_TEST(compile_code_with_params_and_freevars);
  RUN_BUFFER_TEST(compile_labels_with_no_labels);
  RUN_BUFFER_TEST(compile_labels_with_one_label);
  RUN_HEAP_TEST(compile_funcall_with_no_params);
  RUN_HEAP_TEST(compile_funcall_with_no_params_and_locals);
  RUN_HEAP_TEST(compile_funcall_with_one_param);
  RUN_HEAP_TEST(compile_funcall_with_one_param_and_locals);
  RUN_HEAP_TEST(compile_funcall_with_two_params_and_locals);
  RUN_HEAP_TEST(compile_nested_funcall);
  RUN_HEAP_TEST(compile_multilevel_funcall);
  RUN_HEAP_TEST(compile_factorial_funcall);
  RUN_BUFFER_TEST(compile_closure_undefined_label);
  RUN_HEAP_TEST(compile_closure_no_freevars);
  RUN_HEAP_TEST(compile_closure_one_freevar);
  RUN_HEAP_TEST(compile_closure_two_freevars);
}

// End Tests

GREATEST_MAIN_DEFS();

int run_tests(int argc, char **argv) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(object_tests);
  RUN_SUITE(ast_tests);
  RUN_SUITE(reader_tests);
  RUN_SUITE(buffer_tests);
  RUN_SUITE(transform_tests);
  RUN_SUITE(compiler_tests);
  GREATEST_MAIN_END();
}

int main(int argc, char **argv) {
  assert(sizeof(word) == 8);
  return run_tests(argc, argv);
}
