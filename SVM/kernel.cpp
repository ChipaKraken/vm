#include "kernel.h"

#include <iostream>
#include <algorithm>

namespace vm
{
    Kernel::Kernel(Scheduler scheduler, std::vector<Memory::ram_type> executables_paths)
        : machine(),
		  processes(),
		  priorities(),
		  scheduler(scheduler),
          _last_issued_process_id(0),
          _last_ram_position(0),
          _current_process_index(0),
          _cycles_passed_after_preemption(0)
    {
        std::for_each(executables_paths.begin(), executables_paths.end(), [&](Memory::ram_type &executable) {
            CreateProcess(executable);
        });

        if (scheduler == FirstComeFirstServed || scheduler == ShortestJob) {

            machine.pic.isr_3 = [&]() {
                // ToDo: Process the first software interrupt for the FCFS or Shortest Job scheduler
				// Unload the current process
				processes.pop_front();
				if(!processes.empty())
				{
					machine.cpu.registers = processes.front().registers;
				}
				else 
				{
					machine.Stop();
				}
            };
        } else if (scheduler == RoundRobin) {
            machine.pic.isr_0 = [&]() {
				// ToDo: Process the timer interrupt for the Round Robin scheduler
				std::cout << "Kernel: processing the timer interrupt." << std::endl;

                if (!processes.empty()) {
                    if (_cycles_passed_after_preemption <= Kernel::_MAX_CYCLES_BEFORE_PREEMPTION)
                    {
                        std::cout << "Kernel: allowing the current process " << processes[_current_process_index].id << " to run." << std::endl;

                        ++_cycles_passed_after_preemption;

                        std::cout << "Kernel: the current cycle is " << _cycles_passed_after_preemption << std::endl;
                    } else {
                        if (processes.size() > 1) {
                            std::cout << "Kernel: switching the context from process " << processes[_current_process_index].id;
                
							processes.front().registers = machine.cpu.registers;
                            processes.front().state = Process::Ready;

							processes.push_back(processes.front());
							processes.pop_front();

                            std::cout << " to process " << processes[_current_process_index].id << std::endl;

							machine.cpu.registers = processes.front().registers;
                            processes.front().state = Process::Running;
                        }

                        _cycles_passed_after_preemption = 0;
                    }
                }

                std::cout << std::endl;
			};

            machine.pic.isr_3 = [&]() {
                processes.pop_front();
				if(!processes.empty())
				{
					machine.cpu.registers = processes.front().registers;
					processes.front().state = Process::Running;
				}
				else 
				{
					machine.Stop();
				}
            };
        } else if (scheduler == Priority) {
            machine.pic.isr_0 = [&]() {
				// ToDo: Process the timer interrupt for the Priority Queue scheduler
				if(!processes.empty()){
					std::cout << "Priority sh." << std::endl;
					processes.front().registers = machine.cpu.registers;
					Process current_process = processes.front();
					--processes.front().priority;
					//reSort(processes);
					_current_process_index = (_current_process_index + 1) % processes.size();
					machine.cpu.registers = processes.front().registers;
				}
			};

            machine.pic.isr_3 = [&]() {
                // ToDo: Process the first software interrupt for the Priority Queue scheduler
				// Unload the current process
				processes.pop_front();
				if(processes.empty()){
					machine.Stop();
				}
            };
        }

		// ToDo

		// ---

        machine.Start();
    }

    Kernel::~Kernel() {}

    void Kernel::CreateProcess(Memory::ram_type &executable)
	{
        std::copy(executable.begin(),
				  executable.end(),
				  machine.memory.ram.begin() + _last_ram_position);

        Process process(_last_issued_process_id++,
					    _last_ram_position,
						_last_ram_position + executable.size());

        _last_ram_position += executable.size();

        // ToDo: add the new process to an appropriate data structure
        processes.push_back(process);

		// ToDo: process the data structure

    }

}
