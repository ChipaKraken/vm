#ifndef MMU_H
#define MMU_H

#include <vector>
#include <stack>
#include <utility>

namespace vm
{
    class MMU
    {
    public:
        typedef std::vector<int> ram_type;
        typedef ram_type::size_type ram_size_type;

        typedef ram_size_type vmem_size_type;
        typedef vmem_size_type page_entry_type;

        typedef std::vector<page_entry_type>  page_table_type;
        typedef page_table_type::size_type page_table_size_type;

        typedef std::pair<page_table_size_type, ram_size_type> page_index_offset_pair_type;

        static const ram_size_type RAM_SIZE = 0xFFFF; // 64 KB
        static const ram_size_type PAGE_SIZE = 0x80;  // 128 B

        static const ram_size_type INVALID_PAGE = 0;

        ram_type ram;
        page_table_type* page_table;

        MMU();
        virtual ~MMU();

        static page_table_type* CreateEmptyPageTable();

        page_index_offset_pair_type GetPageIndexAndOffsetForVirtualAddress(vmem_size_type address);

        page_entry_type AcquireFrame();
        void ReleaseFrame(page_entry_type page);

    private:
		// TODO: data structures used by the frame allocator

		std::stack<page_entry_type> free_frames;
    };
}

#endif
