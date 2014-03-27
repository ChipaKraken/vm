#include "machine.h"

namespace vm
{
    Machine::Machine()
        : memory(), pic(), pit(pic), cpu(memory, pic),
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
