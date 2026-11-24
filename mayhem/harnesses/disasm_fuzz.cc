// libFuzzer harness for the Bochs x86 instruction decoder + disassembler
// (cpu/decoder), the code behind the bxdisasm tool, built the same way
// (-DBX_STANDALONE_DECODER). First byte: bit0/1 select 16/32/64-bit mode,
// bit2 enables APX. The rest is an instruction stream decoded instruction by
// instruction in both Intel and AT&T syntax, as bxdisasm's disasm_string() does.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "config.h"
#include "cpu/decoder/instr.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1) return -1;
  unsigned m = data[0] & 3;
  bool is_64 = (m == 2), is_32 = (m != 0);
  bool apx_ok = (data[0] & 4) != 0;
  data++; size--;
  // The decoder reads up to 16 bytes ahead of the current instruction
  // (x86 max instruction length is 15); bxdisasm pads its buffer the same way.
  Bit8u *buf = new Bit8u[size + 32];
  memcpy(buf, data, size);
  memset(buf + size, 0, 32);
  char disbuf[512];
  size_t pos = 0;
  while (pos < size) {
    bxInstruction_c i;
    disasm(buf + pos, is_32, is_64, disbuf, &i, 0, 0, BX_DISASM_INTEL, apx_ok);
    bxInstruction_c j;
    disasm(buf + pos, is_32, is_64, disbuf, &j, 0, 0, BX_DISASM_GAS, apx_ok);
    unsigned ilen = i.ilen();
    if (ilen == 0) ilen = 1;
    pos += ilen;
  }
  delete[] buf;
  return 0;
}
