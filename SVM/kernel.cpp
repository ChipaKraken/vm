#include "kernel.h"

#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <limits>

namespace vm
{
	Kernel::Kernel(Scheduler scheduler, std::vector<std::string> executables_paths)
		: machine(),
		processes(),
		priorities(),
		scheduler(scheduler),
		_last_issued_process_id(0),
		_current_process_index(0), 
		_cycles_passed_after_preemption(0)
	{
		// Memory

		machine.mmu.ram[0] = _free_physical_memory_index = 0;
		machine.mmu.ram[1] = machine.mmu.ram.size() - 2;

		// Process page faults (find an empty frame)
		machine.pic.isr_4 = [&]()
		{
			std::cout << "Kernel: page fault." << std::endl;

			MMU::page_entry_type page = machine.cpu.registers.a;
			MMU::page_entry_type frame = machine.mmu.AcquireFrame();

			if(frame != MMU::INVALID_PAGE)
			{
				(*(machine.mmu.page_table))[page] = frame;

			}
			else
			{
				machine.Stop();
			}
		};

		// Process Management

		std::for_each(executables_paths.begin(), executables_paths.end(), [&](const std::string &path) {
			CreateProcess(path);
		});

		if (!processes.empty()) {
			std::cout << "Kernel: setting the first process: " << processes[_current_process_index].id << " for execution." << std::endl;

			machine.cpu.registers = processes[_current_process_index].registers;
			machine.mmu.page_table = processes[_current_process_index].page_table;

			processes[_current_process_index].state = Process::Running;
		}

		if (scheduler == FirstComeFirstServed || scheduler == ShortestJob) {
			machine.pic.isr_0 = [&]() {};
			machine.pic.isr_3 = [&]() {};
		} else if (scheduler == RoundRobin) {
			machine.pic.isr_0 = [&]() {
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
				
							processes[_current_process_index].registers = machine.cpu.registers;
							processes[_current_process_index].state = Process::Ready;

							_current_process_index = (_current_process_index + 1) % processes.size();

							std::cout << " to process " << processes[_current_process_index].id << std::endl;

							machine.cpu.registers = processes[_current_process_index].registers;
							machine.mmu.page_table = processes[_current_process_index].page_table;

							processes[_current_process_index].state = Process::Running;
						}

						_cycles_passed_after_preemption = 0;
					}
				}

				std::cout << std::endl;
			};
			machine.pic.isr_3 = [&]() {
				std::cout << "Kernel: processing the first software interrupt." << std::endl;

				if (!processes.empty()) {
					std::cout << "Kernel: unloading the process " << processes[_current_process_index].id << std::endl;

					// TODO: free process memory with FreePhysicalMemory
					FreeMemory(processes[_current_process_index].memory_start_position);
					processes.erase(processes.begin() + _current_process_index);

					if (processes.empty()) {
						_current_process_index = 0;

						std::cout << "Kernel: no more processes. Stopping the machine." << std::endl;

						machine.Stop();
					} else {
						if (_current_process_index >= processes.size()) {
							_current_process_index %= processes.size();
						}

						std::cout << "Kernel: switching the context to process " << processes[_current_process_index].id << std::endl;

						machine.cpu.registers = processes[_current_process_index].registers;
						machine.mmu.page_table = processes[_current_process_index].page_table;

						processes[_current_process_index].state = Process::Running;

						_cycles_passed_after_preemption = 0;
					}
				}

				std::cout << std::endl;
			};
		} else if (scheduler == Priority) {
			machine.pic.isr_0 = [&]() {};
			machine.pic.isr_3 = [&]() {};
		}

		machine.Start();
	}

	Kernel::~Kernel() {}

	void Kernel::CreateProcess(const std::string &name)
	{
		if (_last_issued_process_id == std::numeric_limits<Process::process_id_type>::max()) {
			std::cerr << "Kernel: failed to create a new process. The maximum number of processes has been reached." << std::endl;
		} else {
			std::ifstream input_stream(name, std::ios::in | std::ios::binary);
			if (!input_stream) {
				std::cerr << "Kernel: failed to open the program file." << std::endl;
			} else {
				MMU::ram_type ops;

				input_stream.seekg(0, std::ios::end);
				auto file_size = input_stream.tellg();
				input_stream.seekg(0, std::ios::beg);
				ops.resize(static_cast<MMU::ram_size_type>(file_size) / 4);

				input_stream.read(reinterpret_cast<char *>(&ops[0]), file_size);

				if (input_stream.bad()) {
					std::cerr << "Kernel: failed to read the program file." << std::endl;
				} else {
					MMU::ram_size_type new_memory_position = AllocateMemory(ops.size()); // TODO: allocate memory for the process (AllocateMemory)
					if (new_memory_position == -1) {
						std::cerr << "Kernel: failed to allocate memory." << std::endl;
					} else {
						std::copy(ops.begin(), ops.end(), (machine.mmu.ram.begin() + new_memory_position));

						Process process(_last_issued_process_id++, new_memory_position,
							new_memory_position + ops.size());
					}
				}
			}
		}
	}

	MMU::vmem_size_type Kernel::VirtualMemoryToPhysical(MMU::ram_size_type previous_index){
		MMU::page_index_offset_pair_type page_index_offset = machine.mmu.GetPageIndexAndOffsetForVirtualAddress(previous_index);
		MMU::page_entry_type page = machine.mmu.page_table->at(page_index_offset.first);

		MMU::page_entry_type frame = machine.mmu.AcquireFrame();
		
		if (page == MMU::INVALID_PAGE){
			processes[_current_process_index].page_table->at(previous_index) = frame;
			return frame + page_index_offset.second;
		}
		else
		{
			machine.Stop();
		}
	}

	MMU::ram_size_type Kernel::AllocateMemory(MMU::ram_size_type units)
	{
		MMU::ram_size_type prev_index = _free_physical_memory_index;
		MMU::ram_size_type current_index;
		

		for(MMU::ram_size_type next_free_index = machine.mmu.ram[VirtualMemoryToPhysical(prev_index)]; ;  prev_index = next_free_index, next_free_index = machine.mmu.ram[next_free_index])
		{
			MMU::ram_size_type size = machine.mmu.ram[VirtualMemoryToPhysical(next_free_index+1)];
			if( size >= units)
			{
				if(size == units)
				{
					machine.mmu.ram[VirtualMemoryToPhysical(prev_index)] = machine.mmu.ram[VirtualMemoryToPhysical(next_free_index)];
				}
				else
				{
					machine.mmu.ram[VirtualMemoryToPhysical(next_free_index + 1)] -= units + 2;
					next_free_index +=  machine.mmu.ram[VirtualMemoryToPhysical(next_free_index + 1)];	

					machine.mmu.ram[VirtualMemoryToPhysical(next_free_index + 1)] = units;
				}
				_free_physical_memory_index = prev_index;

				return next_free_index + 2;

			}
			if(next_free_index == _free_physical_memory_index)
			{
				return NULL;
			}
		}

		return -1;
	}

	void Kernel::FreeMemory(MMU::ram_size_type physical_memory_index)
	{
		MMU::ram_size_type previous_free_block_index = _free_physical_memory_index;
		MMU::ram_size_type current_block_index = physical_memory_index - 2;

		for(; !(current_block_index > previous_free_block_index && current_block_index < machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)]);
			previous_free_block_index =  machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)])	{

				if( previous_free_block_index >= machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)] && 
					((current_block_index > previous_free_block_index || current_block_index < machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)]))){
					break;
				}

		}

		if(current_block_index + machine.mmu.ram[VirtualMemoryToPhysical(current_block_index + 1)] == machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)])
		{
			machine.mmu.ram[VirtualMemoryToPhysical(current_block_index)] == machine.mmu.ram[machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)]];
			machine.mmu.ram[VirtualMemoryToPhysical(current_block_index + 1)] +=  machine.mmu.ram[machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index + 1)]];
		}
		else
		{
			machine.mmu.ram[VirtualMemoryToPhysical(current_block_index)] = machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)];
		}

		if(previous_free_block_index + machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index + 1)] == current_block_index)
		{
			machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index + 1)] += machine.mmu.ram[VirtualMemoryToPhysical(current_block_index + 1)];
			machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)] = machine.mmu.ram[VirtualMemoryToPhysical(current_block_index)];
		}
		else
		{
			machine.mmu.ram[VirtualMemoryToPhysical(previous_free_block_index)] = current_block_index;
		}

		_free_physical_memory_index = previous_free_block_index;
	}
}
