#ifndef PIC_H
#define PIC_H

#include <functional>

namespace vm
{
    class PIC
    {
    public:
        typedef std::function<void()> isr_type;

        // Hardware Interrupts

        isr_type isr_0; // Timer
        isr_type isr_1;
        isr_type isr_2;

        // Software Interrupts
        
        isr_type isr_3;
        isr_type isr_4;
        isr_type isr_5;

        PIC();
        virtual ~PIC();
    };
}

#endif
