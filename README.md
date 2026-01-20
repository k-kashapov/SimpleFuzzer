# SimpleFuzzer

## Build

```
$ make
clang++ user.cpp -gdwarf-2 -fsanitize=fuzzer -c -o user.o -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,trace-stores,trace-loads,inline-8bit-counters -O0
clang++ tester.cpp user.o -o fuzzer.elf -gdwarf-2
```

## Usage

1. Implement logic for testing in user.cpp.
2. Provide entry point with signature `extern "C" int FuzzerTestOneInput(const unsigned char *data, unsigned long len)`;
3. Compile with `make`
4. Run with `./fuzzer.elf`

## Example output

```
$ ./fuzzer.elf 
Coverage-Guided Fuzzer
Starting fuzzing with 6 seeds
Initial coverage: 2 edges
Executions: 0, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 1000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 2000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 3000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 4000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 5000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 6000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
...
Executions: 937000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 938000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 939000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Executions: 940000, Corpus: 7, Coverage: 4, PCs: 3, Crashes: 0
Caught exception: Another crash!

CRASH! Saved to crash_1.bin

Fuzzing Statistics
Total executions: 940747
Final corpus size: 10
Edge coverage: 17
Unique PCs: 5
Unique crashes: 1

$ cat coverage_report.txt 
Edge coverage bitmap (size=17):
Edge 0x5c40960872b0
...
Edge 0x5c4096087320

Unique PCs covered: 5
PC: 0x5c409607aa90
...
PC: 0x74f2be229ebb

```
