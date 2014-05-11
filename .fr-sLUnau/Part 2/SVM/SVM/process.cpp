#include "process.h"

namespace vm
{
    Process::Process(process_id_type id, MMU::ram_size_type memory_start_position,
                                         MMU::ram_size_type memory_end_position)
        : id(id), registers(), state(Ready), priority(0),
          memory_start_position(memory_start_position),
          memory_end_position(memory_end_position)
    {
        registers.ip = memory_start_position;

        sequential_instruction_count = (memory_end_position - memory_start_position) / 2;

        page_table = MMU::CreateEmptyPageTable();
    }

    Process::~Process()
    {
        delete page_table;
    }

    bool Process::operator<(const Process &anotherProcess) const {
        return priority < anotherProcess.priority;
    }
}
