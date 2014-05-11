#include "mmu.h"

namespace vm
{
    MMU::MMU()
        : ram(RAM_SIZE)
    {
      
		for(page_entry_type frame = PAGE_SIZE; frame < RAM_SIZE; frame += PAGE_SIZE)
		{
			free_frames.push(frame);
		}
    }

    MMU::~MMU() {}

    MMU::page_table_type* MMU::CreateEmptyPageTable()
    {
		return new page_table_type(RAM_SIZE / PAGE_SIZE);
    }

    MMU::page_index_offset_pair_type MMU::GetPageIndexAndOffsetForVirtualAddress(vmem_size_type address)
    {
        page_index_offset_pair_type result = std::make_pair((page_table_size_type) -1, (ram_size_type) -1);

		result.first = address / PAGE_SIZE;
		result.second = address % PAGE_SIZE;

        return result;
    }

    MMU::page_entry_type MMU::AcquireFrame()
    {
		if(!free_frames.empty())
		{
			page_entry_type result = free_frames.top();
			free_frames.pop();
			return result;
		}
        return INVALID_PAGE;
    }
    
    void MMU::ReleaseFrame(page_entry_type page)
    {
		free_frames.push(page);
    }
}
