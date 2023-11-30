#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here


from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
import logging
import struct


def traceFunction(call_address, trace, search_functions=None):
    target_function = getFunctionAt(call_address)

    if not target_function:
        return

    parms_data = dump_call_parm_value(call_address)
    for call_addr in parms_data:
        call_parms = parms_data[call_addr]
        parm_data_string = ""
        for parm in sorted(call_parms['parms'].keys()):
            parm_value = call_parms['parms'][parm]['parm_value']
            parm_data = call_parms['parms'][parm]['parm_data']
            if parm_value:
                parm_data_string += "{}({:#010x}), ".format(parm_data, parm_value)
            else:
                parm_data_string += "{}({}), ".format(parm_data, parm_value)
        parm_data_string = parm_data_string.strip(', ')
        print("{}".format(trace))
        print("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, parm_data_string,
                                                            call_parms['call_addr'].offset,
                                                            call_parms['refrence_function_name'],
                                                            call_parms['refrence_function_addr'].offset
                                                            ))
        print("\n")
        if not 'call_parms' in locals():
            print("Finished recursion")
            return

        traceFunction(call_parms['refrence_function_addr'], trace+1)

    print("\n")

    if not 'call_parms' in locals():
        print("Finished recursion")
        return
            

def find_prev_reg(instruction_address, register, max_iter):
    for i in range(max_iter):        
        instruction = getInstructionAt(toAddr(instruction_address))
        instruction_address = instruction.getPrevious().getAddress()
        instruction = getInstructionAt(instruction_address)
        instruction_address = int("0x{}".format(instruction_address.toString()), 16)
        # instruction_address = int("0x{}".format(instruction_address.toString()), 16)
        # print("{}: {}".format(instruction_address, instruction))

        if len(instruction.getOpObjects(0)) == 0:
            return "DONE"
        
        op = instruction.getOpObjects(0)[0]
        if op == register:
            print("FOUND INITIALIZATION")
            return instruction_address
    print("COULD NOT FIND INITIALIZATION")
        


def print_register_operands_of_instruction(instruction_address, max_iter):
    """
    Given an instruction address, find the addresses of the operands of that instruction
    that are registers and print them out.

    :param instruction_address: The address of the instruction to analyze.
    """
    instruction = getInstructionAt(toAddr(instruction_address))
    # print(instruction.getPrevious().getAddress())

    if not instruction:
        logger.error("No instruction found at address: {0:#010x}".format(instruction_address))
        return

    print("Instruction at {0:#010x}: {1}".format(instruction_address, instruction))

    op = instruction.getOpObjects(1)[0]
    opcode = "{}".format(instruction).split(' ')[0]
    
    if not isinstance(op, ghidra.program.model.lang.Register):
        return

    x = ((opcode == "MOV") or (opcode == "LEA") or (opcode == "MOVSX"))
    if opcode:
        print("\nExamine {}...".format(op))
        new_addr = find_prev_reg(instruction_address, op, max_iter)
        if new_addr == "DONE":
            print('\n')
            return
        print_register_operands_of_instruction(new_addr, max_iter)

    else:
        new_addr = find_prev_reg(instruction_address, op, max_iter)
        if not new_addr == "DONE":
            print_register_operands_of_instruction(new_addr, max_iter)
        print('\n')

        op = instruction.getOpObjects(0)[0]
        new_addr = find_prev_reg(instruction_address, op, max_iter)
        if new_addr == "DONE":
            print('\n')
            return
        print_register_operands_of_instruction(new_addr, max_iter)
                


                



if __name__ == '__main__':
    search_functions = None

    instruction_addr = askLong("Input instruction address", "Please input the instruction address")
    print_register_operands_of_instruction(instruction_addr, 100)

