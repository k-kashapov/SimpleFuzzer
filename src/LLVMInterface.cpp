#include <cstdint>
#include <stdexcept>

// LLVM SanitizerCoverage interface
extern "C" {
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);

void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
    // [pcs_beg,pcs_end) is the array of ptr-sized integers representing
    // pairs [PC,PCFlags] for every instrumented block in the current DSO.
    // Capture this array in order to read the PCs and their Flags.
    // The number of PCs and PCFlags for a given DSO is the same as the number
    // of 8-bit counters (-fsanitize-coverage=inline-8bit-counters), or
    // boolean flags (-fsanitize-coverage=inline=bool-flags), or trace_pc_guard
    // callbacks (-fsanitize-coverage=trace-pc-guard).
    // A PCFlags describes the basic block:
    //  * bit0: 1 if the block is the function entry block, 0 otherwise.
}

// Called before a comparison instruction.
// Arg1 and Arg2 are arguments of the comparison.
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {}
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {}
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {}
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {}

// Called before a comparison instruction if exactly one of the arguments is constant.
// Arg1 and Arg2 are arguments of the comparison, Arg1 is a compile-time constant.
// These callbacks are emitted by -fsanitize-coverage=trace-cmp since 2017-08-11
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {}
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {}
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {}
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {}

// Called before a switch statement.
// Val is the switch operand.
// Cases[0] is the number of case constants.
// Cases[1] is the size of Val in bits.
// Cases[2:] are the case constants.
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {}

// Called before a division statement.
// Val is the second argument of division.
void __sanitizer_cov_trace_div4(uint32_t Val) {
    if (Val == 0) {
        throw std::runtime_error("Divison by zero!");
    }
}
void __sanitizer_cov_trace_div8(uint64_t Val) {
    if (Val == 0) {
        throw std::runtime_error("Divison by zero!");
    }
}

// Called before a GetElementPtr (GEP) instruction
// for every non-constant array index.
void __sanitizer_cov_trace_gep(uintptr_t Idx) {}

// Called before a load of appropriate size. Addr is the address of the load.
void __sanitizer_cov_load1(uint8_t *addr) {
    if (addr < (uint8_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_load2(uint16_t *addr) {
    if (addr < (uint16_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_load4(uint32_t *addr) {
    if (addr < (uint32_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_load8(uint64_t *addr) {
    if (addr < (uint64_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_load16(__int128 *addr) {
    if (addr < (__int128*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

// Called before a store of appropriate size. Addr is the address of the store.
void __sanitizer_cov_store1(uint8_t *addr) {
    if (addr < (uint8_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_store2(uint16_t *addr) {
    if (addr < (uint16_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_store4(uint32_t *addr) {
    if (addr < (uint32_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_store8(uint64_t *addr) {
    if (addr < (uint64_t*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

void __sanitizer_cov_store16(__int128 *addr) {
    if (addr < (__int128*)10000) {
        throw std::runtime_error("Nullptr dereference!\n");
    }
}

// 8-bit counters for edge coverage
uint8_t *__sanitizer_cov_counter_beg;
uint8_t *__sanitizer_cov_counter_end;
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);

// PC table for better coverage
uintptr_t *__sanitizer_cov_pcs_beg;
uintptr_t *__sanitizer_cov_pcs_end;

thread_local uintptr_t __sancov_lowest_stack;
}
