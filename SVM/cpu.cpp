#include "cpu.h"

#include <iostream>

namespace vm
{
    Registers::Registers()
        : a(0), b(0), c(0), flags(0), ip(0), sp(0) {}

    CPU::CPU(Memory &memory, PIC &pic): registers(), _memory(memory), _pic(pic) {}

    CPU::~CPU() {}

    void CPU::Step()
    {
        int ip = registers.ip;

        int instruction = _memory.ram[ip];
        int data = _memory.ram[ip + 1];

        if (instruction == CPU::MOVA_BASE_OPCODE) {
            registers.a = data;
            registers.ip += 2;
        } else if (instruction == CPU::MOVB_BASE_OPCODE) {
            registers.b = data;
            registers.ip += 2;
        } else if (instruction == CPU::MOVC_BASE_OPCODE) {
            registers.c = data;
            registers.ip += 2;
        } else if (instruction == CPU::JMP_BASE_OPCODE) {
            registers.ip += data;
        } else if (instruction == CPU::INT_BASE_OPCODE) {
			switch (data)
			{
				case 1:
					_pic.isr_3();
					break;
				// ...
				//case 2:
			    //	_pic.isr_4();
				//	break;
			}
			registers.ip += 2;
        } else {
            std::cerr << "CPU: invalid opcode data. Skipping..." << std::endl;
            registers.ip += 2;
        }
    }
}
