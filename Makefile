CXX=clang++

all:
	@mkdir build -p
	@echo "CXX src/user.cpp"
	@$(CXX) src/user.cpp -gdwarf-2 -fsanitize=fuzzer -c -o build/user.o -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,trace-stores,trace-loads,inline-8bit-counters -O0
	@echo "CXX src/main.cpp src/LLVMInterface.cpp"
	@$(CXX) src/main.cpp src/LLVMInterface.cpp build/user.o -o build/fuzzer.elf -gdwarf-2 -I include
