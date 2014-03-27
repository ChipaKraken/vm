#ifndef PIC_H
#define PIC_H

#include <functional>

namespace vm
{
	// Interrupt Controller (Programmable Interrupt Controller)
	//
	// IRQ: Interrupt Request
	// ISR: Interrupt Service Routine
    class PIC
    {
    public:
        typedef std::function<void()> isr_type;

        // Hardware Interrupts (interrupt service routines that are called for incoming hardware events)

        isr_type isr_0; // IRQ 0: Timer
        isr_type isr_1; // IRQ 1: Keyboard
        isr_type isr_2; // IRQ 2: ...TBD

        // Software Interrupts (interrupt service routines that are called by executing the 'int' CPU instruction)

        isr_type isr_3; // Kernel should decide how to use them
        isr_type isr_4;
        isr_type isr_5;
		isr_type isr_6;
		isr_type isr_7;
		isr_type isr_8;
		isr_type isr_9;
		isr_type isr_10;
		isr_type isr_11;
		isr_type isr_12;
		isr_type isr_13;
		isr_type isr_14;
		isr_type isr_15;
		isr_type isr_16;

        PIC();
        virtual ~PIC();
    };
}

#endif
