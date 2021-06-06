#define _GNU_SOURCE
#include "jit-reader.h"
#include <assert.h> /* for assert */
#include <stddef.h> /* for NULL */
#include <stdint.h> // for int32_t, etc
#include <stdio.h>  /* for fprintf */
#include <stdlib.h>
#include <string.h>   /* for memcpy */
#include <sys/mman.h> /* for mmap */
#undef _GNU_SOURCE

typedef int64_t word;
typedef uint64_t uword;

const word kWordSize = sizeof(word);

// clang-format off
const unsigned char kProgram[] = {
    // mov eax, 42 (0x2a)
    0xb8, 0x2a, 0x00, 0x00, 0x00,
    // int 3 (debug trap)
    0xcc,
    // ret
    0xc3,
};
// clang-format on

const word kProgramSize = sizeof kProgram;

typedef struct {
  char *name;
  void *code;
  word code_size;
} Function;

typedef word (*Entrypoint)();

static void *allocate_executable(const void *code, word code_size) {
  void *result = mmap(/*addr=*/NULL, code_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE,
                      /*filedes=*/-1, /*off=*/0);
  assert(result != NULL && "mmap failed");
  memcpy(result, code, code_size);
  int mprotect_result = mprotect(result, kProgramSize, PROT_EXEC);
  assert(mprotect_result == 0 && "mprotect failed");
  return result;
}

Function *Function_new(const char *name, const void *code, word code_size) {
  Function *result = malloc(sizeof *result);
  assert(result != NULL && "could not allocate function");
  result->name = strdup(name);
  result->code = allocate_executable(code, code_size);
  result->code_size = code_size;
  return result;
}

uword Function_address(Function *function) { return (uword)function->code; }

word Function_call(Function *function) {
  Entrypoint ptr = *(Entrypoint *)&function->code;
  return ptr();
}

void Function_del(Function *function) {
  free(function->name);
  int munmap_result = munmap(function->code, function->code_size);
  assert(munmap_result == 0 && "munmap failed");
  free(function);
}

Function *g_function = NULL;

enum gdb_status Debug_read(struct gdb_reader_funcs *self,
                           struct gdb_symbol_callbacks *cb, void *memory,
                           long memory_sz) {
  (void)self;
  (void)memory_sz;
  fprintf(stderr, "Debug_read called\n");
  if (memory == g_function->code) {
    struct gdb_object *obj = cb->object_open(cb);
    struct gdb_symtab *symtab = cb->symtab_open(cb, obj, "samplefile.lol");
    cb->block_open(cb, symtab, /*parent=*/NULL, (GDB_CORE_ADDR)kProgram,
                   (GDB_CORE_ADDR)(kProgram + kProgramSize), "samplefunction");
    cb->symtab_close(cb, symtab);
    cb->object_close(cb, obj);
    return GDB_SUCCESS;
  }
  return GDB_FAIL;
}

typedef enum {
  kRax = 0,
  kRdx,
  kRcx,
  kRbx,
  kRsi,
  kRdi,
  kRbp,
  kRsp,
  kR8,
  kR9,
  kR10,
  kR11,
  kR12,
  kR13,
  kR14,
  kR15,
  kRA,
} DwarfRegister;

uword Register_read(struct gdb_unwind_callbacks *cb, int reg) {
  struct gdb_reg_value *reg_value = cb->reg_get(cb, reg);
  assert(reg_value != NULL);
  assert(reg_value->size == kWordSize);
  assert(reg_value->defined);
  uword result;
  memcpy(&result, reg_value->value, sizeof result);
  reg_value->free(reg_value);
  return result;
}

static void free_reg_value(struct gdb_reg_value *value) { free(value); }

void Register_write(struct gdb_unwind_callbacks *cb, int reg, uword value) {
  struct gdb_reg_value *gdb_value = malloc(sizeof *gdb_value + kWordSize - 1);
  gdb_value->defined = 1;
  gdb_value->free = free_reg_value;
  memcpy(gdb_value->value, &value, kWordSize);
  cb->reg_set(cb, reg, gdb_value);
}

enum gdb_status Debug_unwind(struct gdb_reader_funcs *self,
                             struct gdb_unwind_callbacks *cb) {
  (void)self;
  fprintf(stderr, "Debug_unwind called\n");
  if (g_function == NULL) {
      fprintf(stderr, "...no function; failing\n");
      return GDB_FAIL;
  }
  uword rip = Register_read(cb, kRA);
  if (rip < Function_address(g_function) ||
      rip >= Function_address(g_function) + g_function->code_size) {
      fprintf(stderr, "...not inside function; failing\n");
    return GDB_FAIL;
  }
  uword rbp = Register_read(cb, kRbp);
  uword rsp = Register_read(cb, kRsp);

  // We haven't modified rbp.
  uword prev_rbp = rbp;
  // The return address is stored on the stack.
  uword prev_rip;
  if (cb->target_read(rsp, &prev_rip, kWordSize) == GDB_FAIL) {
      fprintf(stderr, "could not read return address; failing\n");
    return GDB_FAIL;
  }
  // TODO(max): Why is this?
  uword prev_rsp = rsp + kWordSize;
  Register_write(cb, kRA, prev_rip);
  Register_write(cb, kRsp, prev_rsp);
  Register_write(cb, kRbp, prev_rbp);
  return GDB_SUCCESS;
}

struct gdb_frame_id Debug_get_frame_id(struct gdb_reader_funcs *self,
                                       struct gdb_unwind_callbacks *cb) {
  (void)self;
  (void)cb;
  fprintf(stderr, "Debug_get_frame_id called\n");
  return (struct gdb_frame_id){.code_address = 0, .stack_address = 0};
}

void Debug_destroy_reader(struct gdb_reader_funcs *self) { free(self); }

// enum gdb_status Debug_target_read(GDB_CORE_ADDR target_mem, void* gdb_buf,
// int len) {
//     fprintf(stderr, "Debug_target_read called\n");
//     memcpy(gdb_buf, (void*)target_mem, len);
//     return GDB_SUCCESS;
// }

GDB_DECLARE_GPL_COMPATIBLE_READER

struct gdb_reader_funcs *gdb_init_reader(void) {
  fprintf(stderr, "gdb_init_reader called\n");
  struct gdb_reader_funcs *result = malloc(sizeof *result);
  result->reader_version = GDB_READER_INTERFACE_VERSION;
  result->priv_data = NULL;
  result->read = Debug_read;
  result->unwind = Debug_unwind;
  result->get_frame_id = Debug_get_frame_id;
  result->destroy = Debug_destroy_reader;
  // result->target_read = Debug_target_read;
  return result;
}

int main() {
  Function *function = Function_new("sample", kProgram, kProgramSize);
  g_function = function;
  word return_code = Function_call(function);
  assert(return_code == 42 && "the assembly was wrong");
  g_function = NULL;
  Function_del(function);
  return 0;
}
