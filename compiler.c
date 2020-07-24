#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "libtap/tap.h"

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

void Buffer_write8(BufferWriter *writer, byte b) {
  assert(writer->pos < writer->buf->len);
  Buffer_at_put(writer->buf, writer->pos++, b);
}

void Buffer_write_arr(BufferWriter *writer, byte *arr, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Buffer_write8(writer, arr[i]);
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

void Buffer_inc_reg(BufferWriter *writer, Register reg) {
  Buffer_write8(writer, 0xff);
  Buffer_write8(writer, 0xc0 + reg);
}

void Buffer_dec_reg(BufferWriter *writer, Register reg) {
  Buffer_write8(writer, 0xff);
  Buffer_write8(writer, 0xc8 + reg);
}

const int kBitsPerByte = 8;

void Buffer_mov_reg_imm32(BufferWriter *writer, Register dst, int32_t src) {
  Buffer_write8(writer, 0xb8 + dst);
  for (size_t i = 0; i < 4; i++) {
    Buffer_write8(writer, (src >> (i * kBitsPerByte)) & 0xff);
  }
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

void Buffer_ret(BufferWriter *writer) { Buffer_write8(writer, 0xc3); }

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
  cmp_ok(0, "==", memcmp(buf->address, arr, sizeof arr), __func__)

#define EXPECT_CALL_EQUALS(buf, expected)                                      \
  cmp_ok(expected, "==", call_intfunction(buf), __func__)

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
  done_testing();
}

// End Testing

int main() { return run_tests(); }
