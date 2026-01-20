#include <iostream>
#include <stdexcept>

int mock(int o) {
    if (o > 96) {
        return 5;
        // return *(int*)(uintptr_t)o;
    } else {
        return 45;
    }
}

extern "C" int FuzzerTestOneInput(const unsigned char *data, unsigned long len) {
    while (len > 40) {
        if (len >= 3) {
            if (data[0] == 0x7F && data[1] >= 'E') {
                if (len >= 10 && data[2] >= 'L' && data[4] <= 'F') {
                    // throw std::runtime_error("Discovered crash!");
                    return 0;
                }
            }
        }

        if (len < 2) {
            return 0;
        }

        if (len >= 30) {
            for (int i = 0; i < len; i++) {
                if (data[i] != 0 && i / data[i] > 50) {
                    return mock(data[0] * 2);
                } else {
                    mock(i);
                }
            }
        }

        // Some branches for coverage
        if (len > 0 && data[0] < 128) {
            // Branch 1
            if (len > 1 && data[1] > 200) {
                // Branch 2
                if (len > 2 && (data[2] & 1)) {
                    // Branch 3
                    throw std::runtime_error("Another crash!\n");
                }
            }
        }

        len -= 30;
        data += 30;
    }

    return 0;
}
