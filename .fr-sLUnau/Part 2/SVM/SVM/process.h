#ifndef PROCESS_H
#define PROCESS_H

#include "cpu.h"
#include "mmu.h"

namespace vm
{
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

        MMU::ram_size_type memory_start_position;
        MMU::ram_size_type memory_end_position;

        MMU::ram_size_type sequential_instruction_count;

        MMU::page_table_type *page_table;

        Process(process_id_type id, MMU::ram_size_type memory_start_position,
                                    MMU::ram_size_type memory_end_position);

        virtual ~Process();

        bool operator<(const Process &anotherProcess) const;
    };
}

#endif
