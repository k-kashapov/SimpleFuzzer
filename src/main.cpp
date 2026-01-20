#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <set>
#include <unordered_set>
#include <vector>

#include "LLVMInterface.h"
#include "Mutator.h"
#include "CoverageCollector.h"
#include "Fuzzer.h"

// Initialize static members
std::unordered_set<uintptr_t> CoverageCollector::coveredPCs;
std::set<uint32_t *> CoverageCollector::visitedEdges;
uint32_t *CoverageCollector::guardStart = nullptr;
uint32_t *CoverageCollector::guardEnd = nullptr;

// LLVM callbacks
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    CoverageCollector::initGuardCounters(start, stop);
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard)
        return; // Duplicate the guard check
    CoverageCollector::recordEdge(guard);

    // Get PC for better coverage tracking
    uintptr_t pc = (uintptr_t)__builtin_return_address(1);
    CoverageCollector::recordPC(pc);
}

void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
    CoverageCollector::init8BitCounters(start, stop);
}

int main(int argc, const char **argv) {
    std::cout << "Coverage-Guided Fuzzer\n";

    LLVMFuzzer *fuzzer;

    if (argc >= 2) {
        fuzzer = new LLVMFuzzer(argv[1]);
    } else {
        fuzzer = new LLVMFuzzer();
    }

    fuzzer->fuzz(2'000'000);
    fuzzer->dumpStats();

    delete fuzzer;

    return 0;
}
