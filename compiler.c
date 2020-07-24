#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
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
  Buffer_at_put(writer->buf, writer->pos++, b);
}

// Testing

Buffer *executable_from_bytes(byte *bytes, size_t len) {
  assert(bytes != NULL);
  Buffer *buf = malloc(sizeof *buf);
  assert(buf != NULL);
  Buffer_init(buf, len);
  BufferWriter writer;
  BufferWriter_init(&writer, buf);
  for (size_t i = 0; i < len; i++) {
    Buffer_write8(&writer, bytes[i]);
  }
  Buffer_make_executable(buf);
  return buf;
}

void Buffer_free(Buffer *buf) {
  assert(buf != NULL);
  Buffer_deinit(buf);
  free(buf);
}

int expect_function_returns(Buffer *buf, int expected) {
  assert(buf != NULL);
  assert(buf->address != NULL);
  assert(buf->state == kExecutable);
  int (*function)() = (int (*)())buf->address;
  return function() == expected;
}

int run_tests() {
  plan(NO_PLAN);
  {
    // mov eax, 0x2a; ret
    byte arr[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
    Buffer *buf = executable_from_bytes(arr, sizeof arr);
    ok(expect_function_returns(buf, 42), "function returns 42");
    Buffer_free(buf);
  }
  {
    // mov eax, 0xff; ret
    byte arr[] = {0xb8, 0xff, 0x00, 0x00, 0x00, 0xc3};
    Buffer *buf = executable_from_bytes(arr, sizeof arr);
    ok(expect_function_returns(buf, 255), "function returns 255");
    Buffer_free(buf);
  }
  done_testing();
}

// End Testing

int main() { return run_tests(); }
