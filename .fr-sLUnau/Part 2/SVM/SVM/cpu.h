#ifndef CPU_H
#define CPU_H

#include "mmu.h"
#include "pic.h"

namespace vm
{
    struct Registers
    {
        int a, b, c;

        int flags;

        unsigned int ip, sp;

        Registers();
    };

    class CPU
    {
    public:
        static const int MOVA_BASE_OPCODE = 0x10;
        static const int MOVB_BASE_OPCODE = MOVA_BASE_OPCODE + 1;
        static const int MOVC_BASE_OPCODE = MOVA_BASE_OPCODE + 2;

		static const int LDA_BASE_OPCODE = 0x20;
		static const int LDB_BASE_OPCODE = LDA_BASE_OPCODE + 1;
		static const int LDC_BASE_OPCODE = LDA_BASE_OPCODE + 2;
			
		static const int STA_BASE_OPCODE = 0x30;
		static const int STB_BASE_OPCODE = STA_BASE_OPCODE + 1;
		static const int STC_BASE_OPCODE = STA_BASE_OPCODE + 2;
		

        static const int JMP_BASE_OPCODE = 0x40;

        static const int INT_BASE_OPCODE = 0x50;

        Registers registers;

        CPU(MMU &mmu, PIC &pic);
        virtual ~CPU();

        void Step();

    private:
        MMU &_mmu;
        PIC &_pic;
    };
}

#endif
