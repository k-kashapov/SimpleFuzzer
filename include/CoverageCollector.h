#ifndef COVERAGE_COLLECTOR_H
#define COVERAGE_COLLECTOR_H

#include <cstdint>
#include <unordered_set>
#include <set>
#include <iostream>

// Coverage collector with thread safety
class CoverageCollector {
  private:
    static std::unordered_set<uintptr_t> coveredPCs;
    static std::set<uint32_t *> visitedEdges;
    static uint32_t *guardStart;
    static uint32_t *guardEnd;

  public:
    static void initGuardCounters(uint32_t *start, uint32_t *stop) {
        guardStart = start;
        guardEnd = stop;
        // Initialize all guards to non-zero
        for (uint32_t *x = start; x < stop; x++) {
            *x = 1; // Non-zero to enable tracing
        }
    }

    static void recordPC(uintptr_t pc) {
        coveredPCs.insert(pc);
    }

    static void recordEdge(uint32_t *guard) {
        // Edge is already counted by the sanitizer's 8-bit counter
        visitedEdges.insert(guard);
    }

    static void init8BitCounters(uint8_t *start, uint8_t *stop) {
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
        return coveredPCs.size();
    }

    static void dumpCoverage(const std::string &filename) {
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

#endif // COVERAGE_COLLECTOR_H
