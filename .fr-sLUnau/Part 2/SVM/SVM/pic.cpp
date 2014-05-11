#include "pic.h"

namespace vm
{
    PIC::PIC()
        : isr_0([]() {}),
          isr_1([]() {}),
          isr_2([]() {}),
          isr_3([]() {}),
          isr_4([]() {}),
          isr_5([]() {}) {}

    PIC::~PIC() {}
}
