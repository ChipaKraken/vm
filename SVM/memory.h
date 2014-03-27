#ifndef MEMORY_H
#define MEMORY_H

#include <vector>

namespace vm
{
	// Physical Memory
    class Memory
    {
    public:
        typedef std::vector<int> ram_type;
        typedef ram_type::size_type ram_size_type;

        static const ram_size_type DEFAULT_RAM_SIZE = 0xFFFF;

        ram_type ram; // array of 'DEFAULT_RAM_SIZE' elements

        Memory();
        virtual ~Memory();
    };
}

#endif
