#include "pit.h"

namespace vm
{
    PIT::PIT(PIC &pic)
        : frequency(DEFAULT_FREQUENCY),
          _passed_cycles_count(0), _pic(pic) {}

    PIT::~PIT() {}

    void PIT::Tick()
    {
        ++_passed_cycles_count;
        
        if (_passed_cycles_count >= frequency) {
            _pic.isr_0(); _passed_cycles_count = 0;
        }
    }
}
