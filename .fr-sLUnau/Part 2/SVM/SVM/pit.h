#ifndef PIT_H
#define PIT_H

#include "pic.h"

namespace vm
{
    class PIT
    {
    public:
        typedef unsigned int frequency_type;

        static const frequency_type DEFAULT_FREQUENCY = 1;

        frequency_type frequency;

        PIT(PIC &pic);
        virtual ~PIT();

        void Tick();

    private:
        frequency_type _passed_cycles_count;

        PIC &_pic;
    };
}

#endif
