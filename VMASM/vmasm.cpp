#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>

static const char *MOV_OPCODE_TOKEN = "mov";
static const char *REGISTER_A_TOKEN = "a";
static const char *REGISTER_B_TOKEN = "b";
static const char *REGISTER_C_TOKEN = "c";
static const int MOVA_BASE_OPCODE = 0x10;
static const int MOVB_BASE_OPCODE = MOVA_BASE_OPCODE + 1;
static const int MOVC_BASE_OPCODE = MOVA_BASE_OPCODE + 2;

static const char *JMP_OPCODE_TOKEN = "jmp";
static const int JMP_BASE_OPCODE = 0x20;

static const char *INT_OPCODE_TOKEN = "int";
static const int INT_BASE_OPCODE = 0x30;

// Converts assembly code to virtual CPU instructions
//	mov a 42 -> 0x10 0x2A

int main(int argc, char *argv[])
{
    int exit_code = 0;

    if (argc >= 3) {
        std::string input_file;

        std::string input_file_name(argv[1]);
        std::string output_file_name(argv[2]);

        std::ifstream input_stream(argv[1]);
        if (!input_stream) {
            std::cerr << "Failed to open the input file." << std::endl;

            return -1;
        }

        std::ofstream output_stream(argv[2], std::ios::out | std::ios::binary);
        if (!output_stream) {
            std::cerr << "Failed to open the output file." << std::endl;

            return -1;
        }

        std::vector<int> ops;

        for (std::string line; std::getline(input_stream, line);) {
            std::stringstream tokens(line); std::string token;
            if (tokens >> token) {
                std::transform(token.begin(), token.end(), token.begin(), tolower);

                if (token == MOV_OPCODE_TOKEN) {
                    int instruction, data;
                    if (tokens >> token) {
                        std::transform(token.begin(), token.end(), token.begin(), tolower);

                        if (token == REGISTER_A_TOKEN) {
                            instruction = MOVA_BASE_OPCODE;
                        } else if (token == REGISTER_B_TOKEN) {
                            instruction = MOVB_BASE_OPCODE;
                        } else if (token == REGISTER_C_TOKEN) {
                            instruction = MOVC_BASE_OPCODE;
                        } else {
                            std::cerr << "Invalid register specifier." << std::endl;

                            return -1;
                        }

                        if (!(tokens >> data)) {
                            std::cerr << "Invalid immediate value." << std::endl;

                            return -1;
                        }

                        ops.push_back(instruction);
                        ops.push_back(data);
                    } else {
                        std::cerr << "Invalid assembly statement." << std::endl;

                        return -1;
                    }
                } else if (token == JMP_OPCODE_TOKEN) {
                    int instruction = JMP_BASE_OPCODE;

                    int data;
                    if (!(tokens >> data)) {
                        std::cerr << "Invalid relative address." << std::endl;
                    }

                    ops.push_back(instruction);
                    ops.push_back(data);
                } else if (token == INT_OPCODE_TOKEN) {
                    int instruction = INT_BASE_OPCODE;
                    
                    int data;
                    if (!(tokens >> data)) {
                        std::cerr << "Invalid interrupt number." << std::endl;

                        return -1;
                    }

                    ops.push_back(instruction);
                    ops.push_back(data);
                }
            }

            input_file.append(line);
        }

        if (input_stream.bad()) {
            std::cerr << "Failed to read the input file." << std::endl;

            return -1;
        }

        output_stream.write(reinterpret_cast<const char *>(&ops[0]), ops.size() * sizeof(int));

        if (output_stream.bad()) {
            std::cerr << "Failed to write the output file." << std::endl;

            return -1;
        }
    } else {
        std::cerr << "The syntax of the command is incorrect." << std::endl <<
                     " vmasm <input file> <output file>"       << std::endl << std::endl;

        return -1;
    }

    return 0;
}
