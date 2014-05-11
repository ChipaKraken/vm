#include <vector>
#include <algorithm>

#include "kernel.h"

int main(int argc, char *argv[])
{
    if (argc > 2) {
        std::string arg(argv[1]);

        vm::Kernel::Scheduler scheduler;
        if (arg == "/scheduler:fcfs") {
            scheduler = vm::Kernel::FirstComeFirstServed;
        } else if (arg == "/scheduler:sf") {
            scheduler = vm::Kernel::ShortestJob;
        } else if (arg == "/scheduler:rr") {
            scheduler = vm::Kernel::RoundRobin;
        } else if (arg == "/scheduler:priority") {
            scheduler = vm::Kernel::Priority;
        }

        std::vector<std::string> processes;
        for (int i = 2; i < argc; ++i) {
            processes.push_back(std::string(argv[i]));
        }

        vm::Kernel kernel(scheduler, processes);
    }

    return 0;
}
