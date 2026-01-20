#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// LLVM SanitizerCoverage interface
extern "C" {
int FuzzerTestOneInput(const unsigned char *data, unsigned long len);

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

// Coverage collector with thread safety
class CoverageCollector {
  private:
    static std::unordered_set<uintptr_t> coveredPCs;
    static std::vector<uint8_t> edgeCounters;
    static std::set<uint32_t *> visitedEdges;
    static std::mutex coverageMutex;
    static uint32_t *guardStart;
    static uint32_t *guardEnd;

  public:
    static void initGuardCounters(uint32_t *start, uint32_t *stop) {
        std::lock_guard<std::mutex> lock(coverageMutex);
        guardStart = start;
        guardEnd = stop;
        // Initialize all guards to non-zero
        for (uint32_t *x = start; x < stop; x++) {
            *x = 1; // Non-zero to enable tracing
        }
    }

    static void recordPC(uintptr_t pc) {
        std::lock_guard<std::mutex> lock(coverageMutex);
        coveredPCs.insert(pc);
    }

    static void recordEdge(uint32_t *guard) {
        // Edge is already counted by the sanitizer's 8-bit counter
        visitedEdges.insert(guard);
    }

    static void init8BitCounters(uint8_t *start, uint8_t *stop) {
        std::lock_guard<std::mutex> lock(coverageMutex);
        edgeCounters.assign(start, stop);
    }

    static void resetExecutionState() {
        // Reset counters for new execution
        if (!visitedEdges.empty() && guardStart) {
            for (auto it = visitedEdges.begin(); it != visitedEdges.end();
                 it = visitedEdges.erase(it)) {
            }
        }
    }

    static std::set<uint32_t *> getEdgeHits() { return visitedEdges; }

    static int getNewCoverage(const std::set<uint32_t *> &prevBitmap) {
        auto current = getEdgeHits();
        return current.size() - prevBitmap.size();
    }

    static int getTotalCoverage() {
        auto bitmap = getEdgeHits();
        return bitmap.size();
    }

    static size_t getUniquePCs() {
        std::lock_guard<std::mutex> lock(coverageMutex);
        return coveredPCs.size();
    }

    static void dumpCoverage(const std::string &filename) {
        std::lock_guard<std::mutex> lock(coverageMutex);
        std::ofstream out(filename);

        out << "Edge coverage bitmap (size=" << visitedEdges.size() << "):\n";
        for (auto edge : visitedEdges) {
            out << "Edge " << edge << "\n";
        }

        out << "\nUnique PCs covered: " << coveredPCs.size() << "\n";
        for (auto pc : coveredPCs) {
            out << "PC: 0x" << std::hex << pc << std::dec << "\n";
        }
    }
};

// Initialize static members
std::unordered_set<uintptr_t> CoverageCollector::coveredPCs;
std::vector<uint8_t> CoverageCollector::edgeCounters;
std::set<uint32_t *> CoverageCollector::visitedEdges;
std::mutex CoverageCollector::coverageMutex;
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

// Mutation strategies
class Mutator {
  private:
    std::mt19937_64 rng;
    std::uniform_int_distribution<int> dist;

  public:
    Mutator() : rng(std::chrono::system_clock::now().time_since_epoch().count()) {}

    std::vector<uint8_t> mutate(const std::vector<uint8_t> &input) {
        if (input.empty())
            return {0};

        std::vector<uint8_t> mutated = input;
        std::uniform_int_distribution<size_t> sizeDist(0, mutated.size() - 1);
        std::uniform_int_distribution<int> opDist(0, 100);
        std::uniform_int_distribution<uint8_t> byteDist(0, 255);

        int ops = 1 + (rng() % 15); // mutations per input

        for (int i = 0; i < ops; i++) {
            int op = opDist(rng) % 128;

            if (op < 30 && mutated.size() > 1) {
                // Flip bits
                size_t pos = sizeDist(rng);
                mutated[pos] ^= (1 << (rng() % 8));
            } else if (op < 60 && mutated.size() < 1024) {
                // Insert byte
                size_t pos = sizeDist(rng) % mutated.size();
                unsigned len = sizeDist(rng) % 256;
                for (unsigned j = 0; j < len; j++) {
                    uint8_t byte = byteDist(rng);
                    mutated.insert(mutated.begin() + pos, byte);
                }
            } else if (op < 80 && mutated.size() > 1) {
                // Delete byte
                size_t pos = sizeDist(rng) % mutated.size();
                mutated.erase(mutated.begin() + pos);
            } else if (op < 90) {
                // Swap bytes
                if (mutated.size() >= 2) {
                    size_t pos1 = sizeDist(rng);
                    size_t pos2 = sizeDist(rng);
                    std::swap(mutated[pos1], mutated[pos2]);
                }
            } else {
                // Add interesting values
                size_t pos = sizeDist(rng);
                if (pos < mutated.size()) {
                    static const uint8_t interesting[] = {
                        0,   1,   0x80, 0xFF, 0x7F, 0x40, 0x3F, 0x11, 'A', 'B', 'C', 'D',
                        'E', 'F', 'G',  'H',  'I',  'J',  'K',  'L',  'M', 'N', 'O', 'P',
                        'Q', 'R', 'S',  'T',  'U',  'V',  'W',  'X',  'Y', 'Z'};
                    mutated[pos] =
                        interesting[rng() % (sizeof(interesting) / sizeof(interesting[0]))];
                }
            }
        }

        return mutated;
    }

    std::vector<uint8_t> crossover(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
        if (a.empty() || b.empty())
            return a.empty() ? b : a;

        std::uniform_int_distribution<size_t> splitDist;
        size_t split = (splitDist(rng) % a.size()) % b.size();

        std::vector<uint8_t> result;
        result.insert(result.end(), a.begin(), a.begin() + split);
        result.insert(result.end(), b.begin() + split, b.end());

        return result;
    }
};

// Fuzzer engine
class LLVMFuzzer {
  private:
    std::vector<std::vector<uint8_t>> corpus;
    std::vector<int> corpusScores;
    Mutator mutator;
    int totalExecutions;
    int uniqueCrashes;

  public:
    LLVMFuzzer() : totalExecutions(0), uniqueCrashes(0) {
        // Initial seeds
        addSeed({});
        addSeed({0});
        addSeed({0xFF});
        addSeed({0x7F});
        addSeed({'A', 'B', 'C'});
        addSeed({0, 1, 2, 3, 4, 5});
    }

    LLVMFuzzer(const std::string &corpus_path) : totalExecutions(0), uniqueCrashes(0) {
        if (std::filesystem::exists(corpus_path)) {
            for (const auto &file : std::filesystem::directory_iterator(corpus_path)) {
                std::ifstream in(file.path(), std::ios::in | std::ios::binary);
                in.unsetf(std::ios::skipws);

                auto size = std::filesystem::file_size(file.path());
                std::vector<uint8_t> seed((std::istreambuf_iterator<char>(in)),
                                          std::istreambuf_iterator<char>());
                addSeed(seed);
            }
        } else {
            LLVMFuzzer();
        }
    }

    void addSeed(const std::vector<uint8_t> &seed) {
        corpus.push_back(seed);
        corpusScores.push_back(0);
    }

    bool executeAndCollect(const std::vector<uint8_t> &input,
                           std::set<uint32_t *> &coverageBitmap) {
        auto prevBitmap = CoverageCollector::getEdgeHits();

        int ret = 0;

        try {
            // Execute target function
            ret = FuzzerTestOneInput(input.data(), input.size());
        } catch (const std::exception &e) {
            std::cerr << "Caught exception: " << e.what() << "\n";
            handleCrash(input);
            throw;
        }

        coverageBitmap = CoverageCollector::getEdgeHits();
        int newCoverage = CoverageCollector::getNewCoverage(prevBitmap);

        if (newCoverage > 0) {
            // Update corpus
            corpus.push_back(input);
            corpusScores.push_back(newCoverage);

            // Trim corpus if too large
            if (corpus.size() > 1000) {
                // Keep top 80% by score, random 20%
                std::vector<size_t> indices(corpus.size());
                std::iota(indices.begin(), indices.end(), 0);

                std::sort(indices.begin(), indices.end(),
                          [&](size_t a, size_t b) { return corpusScores[a] > corpusScores[b]; });

                std::vector<std::vector<uint8_t>> newCorpus;
                std::vector<int> newScores;

                size_t keep = 800;
                for (size_t i = 0; i < keep && i < indices.size(); i++) {
                    newCorpus.push_back(corpus[indices[i]]);
                    newScores.push_back(corpusScores[indices[i]]);
                }

                std::shuffle(indices.begin(), indices.end(), std::mt19937(std::random_device{}()));

                for (size_t i = keep; i < 200 && i < indices.size(); i++) {
                    newCorpus.push_back(corpus[indices[i]]);
                    newScores.push_back(corpusScores[indices[i]]);
                }

                corpus = newCorpus;
                corpusScores = newScores;
            }

            return true;
        }

        return false;
    }

    void fuzz(int maxExecutions = 100000) {
        std::cout << "Starting fuzzing with " << corpus.size() << " seeds\n";
        std::cout << "Initial coverage: " << CoverageCollector::getTotalCoverage() << " edges\n";

        std::uniform_int_distribution<size_t> corpusDist;
        std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());

        for (int i = 0; i < maxExecutions; i++) {
            totalExecutions++;

            // Select input from corpus (weighted by score)
            std::vector<size_t> weightedIndices;
            for (size_t j = 0; j < corpus.size(); j++) {
                int weight = std::max(1, corpusScores[j]);
                for (int w = 0; w < weight; w++) {
                    weightedIndices.push_back(j);
                }
            }

            if (weightedIndices.empty())
                continue;

            std::uniform_int_distribution<size_t> weightedDist(0, weightedIndices.size() - 1);
            size_t idx = weightedIndices[weightedDist(rng)];
            const auto &parent = corpus[idx];

            // Mutate
            auto mutated = mutator.mutate(parent);

            try {
                // Execute
                std::set<uint32_t *> coverage;
                executeAndCollect(mutated, coverage);

                // Random input
                std::set<uint32_t *> coverage_rand;
                std::vector<uint8_t> rand_input;
                unsigned long len = corpusDist(rng) % 100;
                for (int i = corpusDist(rng); i < len; i++) {
                    rand_input.push_back(static_cast<uint8_t>(corpusDist(rng)));
                }

                executeAndCollect(rand_input, coverage_rand);

                // Occasionally try crossover
                if (i % 10 == 0 && corpus.size() >= 2) {
                    size_t idx1 = corpusDist(rng) % corpus.size();
                    size_t idx2 = corpusDist(rng) % corpus.size();
                    if (idx1 != idx2) {
                        auto crossed = mutator.crossover(corpus[idx1], corpus[idx2]);
                        executeAndCollect(crossed, coverage);
                    }
                }

            } catch (...) {
                break;
            }

            // Progress report
            if (i % 1000 == 0) {
                std::cout << "Executions: " << i << ", Corpus: " << corpus.size()
                          << ", Coverage: " << CoverageCollector::getTotalCoverage()
                          << ", PCs: " << CoverageCollector::getUniquePCs()
                          << ", Crashes: " << uniqueCrashes << "\n";
            }
        }
    }

    void dumpStats() {
        std::cout << "\nFuzzing Statistics\n";
        std::cout << "Total executions: " << totalExecutions << "\n";
        std::cout << "Final corpus size: " << corpus.size() << "\n";
        std::cout << "Edge coverage: " << CoverageCollector::getTotalCoverage() << "\n";
        std::cout << "Unique PCs: " << CoverageCollector::getUniquePCs() << "\n";
        std::cout << "Unique crashes: " << uniqueCrashes << "\n";

        // Save interesting inputs
        std::filesystem::create_directories("fuzz_corpus");
        for (size_t i = 0; i < corpus.size(); i++) {
            std::ofstream out("fuzz_corpus/input_" + std::to_string(i) + ".bin", std::ios::binary);
            out.write(reinterpret_cast<const char *>(corpus[i].data()), corpus[i].size());
        }

        CoverageCollector::dumpCoverage("coverage_report.txt");
    }

  private:
    void handleCrash(const std::vector<uint8_t> &input) {
        uniqueCrashes++;

        std::filesystem::create_directories("crashes");
        // Save crashing input
        std::ofstream out("crashes/crash_" + std::to_string(uniqueCrashes) + ".bin",
                          std::ios::binary);
        out.write(reinterpret_cast<const char *>(input.data()), input.size());

        std::cout << "CRASH! Saved to crash_" << uniqueCrashes << ".bin\n";
    }
};

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
