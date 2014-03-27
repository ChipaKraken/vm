#ifndef KERNEL_H
#define KERNEL_H

#include <deque>
#include <queue>
#include <string>

#include "machine.h"
#include "process.h"

namespace vm
{
	// OS Kernel
    class Kernel
    {
    public:
        enum Scheduler
        {
            FirstComeFirstServed,
            ShortestJob,
            RoundRobin,
            Priority
        };

        typedef std::deque<Process> process_list_type;
        typedef std::priority_queue<Process> process_priorities_type;

        Machine machine;

        process_list_type processes;
        process_priorities_type priorities;

        Scheduler scheduler;

        Kernel(Scheduler scheduler, std::vector<Memory::ram_type> executables_paths); // Kernel boot process (setup ISRs, create processes, etc.)
        virtual ~Kernel();

        void CreateProcess(Memory::ram_type &executable); // Creates a new PCB, places the executable image into memory

    private:
        static const unsigned int _MAX_CYCLES_BEFORE_PREEMPTION = 100;

        Process::process_id_type _last_issued_process_id;
        Memory::ram_type::size_type _last_ram_position;

        unsigned int _cycles_passed_after_preemption;
        process_list_type::size_type _current_process_index;
    };
}

#endif
