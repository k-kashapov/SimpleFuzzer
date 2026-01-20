#ifndef LLVM_INTERFACE_H
#define LLVM_INTERFACE_H

#include <cstdint>

extern "C" {
int FuzzerTestOneInput(const unsigned char *data, unsigned long len);

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end);
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2);
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2);
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases);
void __sanitizer_cov_trace_div4(uint32_t Val);
void __sanitizer_cov_trace_div8(uint64_t Val);
void __sanitizer_cov_trace_gep(uintptr_t Idx);
void __sanitizer_cov_load1(uint8_t *addr);
void __sanitizer_cov_load2(uint16_t *addr);
void __sanitizer_cov_load4(uint32_t *addr);
void __sanitizer_cov_load8(uint64_t *addr);
void __sanitizer_cov_load16(__int128 *addr);
void __sanitizer_cov_store1(uint8_t *addr);
void __sanitizer_cov_store2(uint16_t *addr);
void __sanitizer_cov_store4(uint32_t *addr);
void __sanitizer_cov_store8(uint64_t *addr);
void __sanitizer_cov_store16(__int128 *addr);
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);

}

#endif // LLVM_INTERFACE_H
