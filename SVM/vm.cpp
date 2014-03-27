#include <vector>
#include <iostream>
#include <fstream>

#include "kernel.h"

namespace vm
{
	Memory::ram_type *LoadExecutable(const std::string &name)
	{
		Memory::ram_type *result = NULL;

		std::ifstream input_stream(name, std::ios::in | std::ios::binary);
		if (!input_stream) {
			std::cerr << "VM: failed to open the program file." << std::endl;
		} else {
			result = new Memory::ram_type();

			input_stream.seekg(0, std::ios::end);
			auto file_size = input_stream.tellg();
			input_stream.seekg(0, std::ios::beg);
			result->resize(static_cast<Memory::ram_size_type>(file_size) / 4);
			input_stream.read(reinterpret_cast<char *>(&(*result)[0]), file_size);

			if (input_stream.bad()) {
				delete result; result = NULL;
				std::cerr << "VM: failed to read the program file." << std::endl;
			}
		}

		return result;
	}
}

int main(int argc, char *argv[])
{
	using namespace vm;

    if (argc > 2) {
        std::string arg(argv[1]);

        Kernel::Scheduler scheduler;
        if (arg == "/scheduler:fcfs") {
            scheduler = Kernel::FirstComeFirstServed;
        } else if (arg == "/scheduler:sf") {
            scheduler = Kernel::ShortestJob;
        } else if (arg == "/scheduler:rr") {
            scheduler = Kernel::RoundRobin;
        } else if (arg == "/scheduler:priority") {
            scheduler = Kernel::Priority;
        }

        std::vector<Memory::ram_type> processes;
        for (int i = 2; i < argc; ++i) {
			Memory::ram_type *executable = LoadExecutable(argv[i]);
			if (executable) {
				processes.push_back(*executable);
				delete executable;
			}
        }

        Kernel kernel(scheduler, processes);
    }

    return 0;
}
