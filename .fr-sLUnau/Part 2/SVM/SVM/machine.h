#ifndef MACHINE_H
#define MACHINE_H

#include "mmu.h"
#include "pic.h"
#include "pit.h"
#include "cpu.h"

namespace vm
{
    class Machine
    {
    public:
        MMU mmu;
        PIC pic;
        PIT pit;
        CPU cpu;

        Machine();
        virtual ~Machine();

        void Start();
        void Stop();

    private:
        bool _working;
    };
}

#endif
