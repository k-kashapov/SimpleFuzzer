#ifndef MUTATOR_H
#define MUTATOR_H

#include <random>
#include <chrono>

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

#endif // MUTATOR_H
