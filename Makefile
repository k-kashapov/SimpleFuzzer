
all:
	clang++ user.cpp -gdwarf-2 -fsanitize=fuzzer -c -o user.o -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,trace-stores,trace-loads,inline-8bit-counters -O0
	clang++ tester.cpp user.o -o fuzzer.elf -gdwarf-2
