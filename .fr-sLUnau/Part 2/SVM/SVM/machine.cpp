#include "machine.h"

namespace vm
{
    Machine::Machine()
        : mmu(), pic(), pit(pic), cpu(mmu, pic),
         _working(false) {}

    Machine::~Machine() {}

    void Machine::Start()
    {
        if (!_working) {
            _working = true;

            while (_working) {
                pit.Tick();
                cpu.Step();
            }
        }
    }

    void Machine::Stop()
    {
        if (_working) {
            _working = false;
        }
    }
}
