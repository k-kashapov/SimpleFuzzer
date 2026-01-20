#ifndef FUZZER_H
#define FUZZER_H

#include <algorithm>
#include <cstdint>
#include <vector>
#include <filesystem>
#include "LLVMInterface.h"
#include "Mutator.h"
#include "CoverageCollector.h"

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
#endif // FUZZER_H
