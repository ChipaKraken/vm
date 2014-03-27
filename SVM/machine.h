#ifndef MACHINE_H
#define MACHINE_H

#include "memory.h"
#include "pic.h"
#include "pit.h"
#include "cpu.h"

namespace vm
{
	// Virtual Machine
	//
	// Combines all components (CPU, memory, timer, interrupt controller)
	// Orchestrates their execution
    class Machine
    {
    public:
        Memory memory;
        PIC pic;
        PIT pit;
        CPU cpu;

        Machine();
        virtual ~Machine();

        void Start(); // Starts the cpu, timer, etc.
        void Stop();  // Stops...

    private:
        bool _working;
    };
}

#endif
