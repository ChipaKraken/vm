#include "cpu.h"

#include <iostream>

namespace vm
{
    Registers::Registers()
        : a(0), b(0), c(0), flags(0), ip(0), sp(0) {}

    CPU::CPU(MMU &mmu, PIC &pic): registers(), _mmu(mmu), _pic(pic) {}

    CPU::~CPU() {}

    void CPU::Step()
    {
        int ip = registers.ip;

        int instruction = _mmu.ram[ip];
        int data = _mmu.ram[ip + 1];

        switch (instruction) {
        case CPU::MOVA_BASE_OPCODE:
            registers.a = data;
            registers.ip += 2;

            break;
        case CPU::MOVB_BASE_OPCODE:
            registers.b = data;
            registers.ip += 2;

            break;
        case CPU::MOVC_BASE_OPCODE:
            registers.c = data;
            registers.ip += 2;

            break;
		case CPU::LDA_BASE_OPCODE:
			MMU::page_index_offset_pair_type page_index_and_offset = 
				_mmu.GetPageIndexAndOffsetForVirtualAddress(data);

			MMU::page_entry_type frame = 
				_mmu.page_table->at(page_index_and_offset.first);

			if(frame == MMU::INVALID_PAGE)
			{
				int temp = registers.a;
				
				registers.a = page_index_and_offset.first;
				_pic.isr_4();

				registers.a = temp;
			}
			else
			{
				registers.a = _mmu.ram[frame + page_index_and_offset.second];
				//eto v ST _mmu.ram[frame + page_index_and_offset.second] = registers.a;
				registers.ip += 2;
			}

			break;
		/*
			TODO:

			case CPU::LDA_BASE_OPCODE:
				Get the page index and physical address offset from MMU for a virtual address in 'data'
				Get the page from the current page table in MMU with the acquired index
				If the page is invalid
					Save the value of register 'a' in a temp. variable
					Place the index of this page into register 'a'
					Call the page fault handler in PIC (isr_4)
					Restore register 'a'
				or else
					Calculate the physical address with the value in the page entry and the physical address offset
					Read or write (for ST...) from/to the physical memory with the calculated address
				
					Increment the instruction pointer

				break;
			case CPU::LDB_BASE_OPCODE:
				...

				break;
			case ...

			case CPU::STA_BASE_OPCODE:
				...

				break;
		*/
        case CPU::JMP_BASE_OPCODE:
            registers.ip += data;

            break;
        case CPU::INT_BASE_OPCODE:
            _pic.isr_3();

            break;
        default:
            std::cerr << "CPU: invalid opcode data (" << instruction << "). Skipping..." << std::endl;
            registers.ip += 2;

            break;
        }
    }
}
