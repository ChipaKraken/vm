#ifndef PROCESS_H
#define PROCESS_H

#include "cpu.h"
#include "memory.h"

namespace vm
{
	// PCB (Process Control Block)
	//
	// Represents a process and its state
    class Process
    {
    public:
        enum States
        {
            Running, Ready, Blocked
        };

        typedef unsigned int process_id_type;
        typedef unsigned short process_priority_type;

        process_id_type id;

        Registers registers;

        States state;

        process_priority_type priority;

        Memory::ram_size_type memory_start_position;
        Memory::ram_size_type memory_end_position;

        Memory::ram_size_type sequential_instruction_count;

        Process(process_id_type id, Memory::ram_size_type memory_start_position,
                                    Memory::ram_size_type memory_end_position);

        virtual ~Process();

        bool operator<(const Process &anotherProcess) const;
    };
}

#endif
