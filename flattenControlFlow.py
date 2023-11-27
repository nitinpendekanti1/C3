from ghidra.app.decompiler import DecompInterface
import logging
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.pcode import PcodeOp, p_code_op_AST
import struct

def log_setup():
    handler = logging.getprogramLog('CustomprogramLog')
    handler.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
    handler.setFormatter(format)
    handler.addHandler(handler)
    return handler

def get_endian_type():
    endian_data = currentProgram.domainFile.getMetadata().get(u'Endian', u'Little')
    return endian_data == u'Big'

def determine_processor_type():
    pr_data = currentProgram.domainFile.getMetadata().get(u'Processor', u'Unknown')
    return pr_data.endswith(u'64')

programLog = log_setup()

func_cache = {}

def is_address_in_current_program(address):
    return any(
        block.getStart().offset <= address.offset < block.getEnd().offset
        for block in currentProgram.memory.blocks
    )

class VarNode:
    def __init__(self, varNode, programLog=None):
        self.varNode = varNode
        self.programLog = programLog or self.log_setup()

    def log_setup(self):
        defaultLog = logging.getprogramLog('VarNode_programLog')
        defaultLog.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
        handler.setFormatter(format)
        defaultLog.addHandler(handler)
        return defaultLog

    def getVal(self):
        type = self.getType()
        self.programLog.debug("varNode {}".format(type))

        if type in ['Address', 'Constant', 'AddrTied', 'Unaffected']:
            return self.varNode.getAddress()
        elif type in ['Unique', 'Register']:
            self.programLog.debug(self.varNode.getDef())
            return pcodeOpCalculation(self.varNode.getDef())
        elif type == 'Persistent':
            return None
        else:
            self.programLog.debug("Unhandled varNode type: {}".format(type))


    def getType(self):
        if self.varNode.isAddress():
            return 'Address'
        elif self.varNode.isConstant():
            return 'Constant'
        elif self.varNode.isUnique():
            return 'Unique'
        elif self.varNode.isRegister():
            return 'Register'
        elif self.varNode.isPersistent():
            return 'Persistent'
        elif self.varNode.isAddrTied():
            return 'AddrTied'
        elif self.varNode.isUnaffected():
            return 'Unaffected'
        else:
            return 'Unknown'



def pcodeOpCalculation(pcode):
    programLog.debug("pcode: {}, type: {}".format(pcode, type(pcode)))

    if not isinstance(pcode, p_code_op_AST):
        programLog.debug("Found Unhandled op: {}".format(pcode))
        return None

    op = pcode.getop()

    if op == PcodeOp.PTRSUB:
        return ptrSub(pcode)

    elif op == PcodeOp.CAST:
        return handleCast(pcode)

    elif op == PcodeOp.PTRADD:
        return ptrAdd(pcode)

    elif op == PcodeOp.INDIRECT:
        return indirect(pcode)

    elif op == PcodeOp.MULTIEQUAL:
        return multiEqual(pcode)

    elif op == PcodeOp.COPY:
        return copyHandling(pcode)

    else:
        programLog.debug("Found Unhandled op: {}".format(op))
        return None

def ptrSub(pcode):
    programLog.debug("PTRSUB")
    node1 = VarNode(pcode.getInput(0))
    node2 = VarNode(pcode.getInput(1))
    val1 = node1.getVal()
    val2 = node2.getVal()

    if isinstance(val1, GenericAddress) and isinstance(val2, GenericAddress):
        return val1.offset + val2.offset
    else:
        programLog.debug("val1: {}".format(val1))
        programLog.debug("val2: {}".format(val2))
        return None

def handleCast(pcode):
    programLog.debug("CAST")
    node1 = VarNode(pcode.getInput(0))
    val1 = node1.getVal()

    if isinstance(val1, GenericAddress):
        return val1.offset
    else:
        return None

def ptrAdd(pcode):
    programLog.debug("PTRADD")
    var0 = VarNode(pcode.getInput(0))
    try:
        val0_point = var0.getVal()

    except Exception as err:
        programLog.debug("Got something wrong with calc PcodeOp.PTRADD : {}".format(err))
        return None

    except:
        programLog.error("Got something wrong with calc PcodeOp.PTRADD ")
        return None

def indirect(pcode):
    programLog.debug("INDIRECT")
    return None

def multiEqual(pcode):
    programLog.debug("MULTIEQUAL")
    return None

def copyHandling(pcode):
    programLog.debug("COPY")
    programLog.debug("input_0: {}".format(pcode.getInput(0)))
    programLog.debug("Output: {}".format(pcode.getOutput()))
    var0 = VarNode(pcode.getInput(0))
    val0 = var0.getVal()
    return val0

class funcAnalysis:
    def __init__(self, function, TTL=30, programLog=programLog):
        self.function = function
        self.TTL = TTL
        self.programLog = programLog if programLog is not None else self.log_setup()
        self.hFunc = None
        self.pcodes_called = {}
        self.prepare()

    def log_setup(self):
        defaultLog = logging.getprogramLog('target')
        defaultLog.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
        handler.setFormatter(format)
        defaultLog.addHandler(handler)
        return defaultLog

    def prepare(self):
        self.hFunc = self.get_h_func()
        self.allCallPcode()

    def get_h_func(self):
        decompiled_libary = DecompInterface()
        decompiled_libary.openProgram(currentProgram)
        TTL = self.TTL
        dRes = decompiled_libary.decompileFunction(self.function, TTL, getMonitor())
        hFunc = dRes.getHighFunc()
        return hFunc

    def get_function_pcode(self):
        try:
            ops = self.hFunc.getPcodeOps()
        except Exception:
            return None
        return ops

    def print_pcodes(self):
        ops = self.get_function_pcode()
        while ops.hasNext():
            p_code_op_AST = ops.next()
            print(p_code_op_AST)
            op = p_code_op_AST.getop()
            print("op: {}".format(op))
            if op == PcodeOp.CALL:
                print("Found a call at 0x{}".format(p_code_op_AST.getInput(0).PCAddress))
                call_addr = p_code_op_AST.getInput(0).getAddress()
                print("Calling {}(0x{}) ".format(getFunctionAt(call_addr), call_addr))
                inputs = p_code_op_AST.getInputs()
                for i in range(1, len(inputs)):
                    parm = inputs[i]
                    print("Parameter {}: {}".format(i, parm))

    def allCallPcode(self):
        ops = self.get_function_pcode()
        if not ops:
            return

        while ops.hasNext():
            p_code_op_AST = ops.next()
            op = p_code_op_AST.getop()
            if op in [PcodeOp.CALL, PcodeOp.CALLIND]:
                op_call_addr = p_code_op_AST.getInput(0).PCAddress
                self.pcodes_called[op_call_addr] = p_code_op_AST

    def callPcode(self, call_address):
        return self.pcodes_called.get(call_address)

    def analyzeCallParms(self, call_address):
        parms = {}
        p_code_op_AST = self.callPcode(call_address)
        if not p_code_op_AST:
            return

        self.programLog.debug("Target call at 0x{} in func {}(0x{})".format(
            p_code_op_AST.getInput(0).PCAddress, self.function.name, hex(self.function.entryPoint.offset)))
        op = p_code_op_AST.getop()
        target_call_addr = (
            VarNode(p_code_op_AST.getInput(0)).getVal() if op == PcodeOp.CALLIND
            else p_code_op_AST.getInput(0).getAddress()
        )
        self.programLog.debug("Target call address: {}".format(target_call_addr))

        inputs = p_code_op_AST.getInputs()
        for i, parm in enumerate(inputs[1:], start=1):
            self.programLog.debug("Parameter {}: {}".format(i, parm))
            parm_node = VarNode(parm)
            self.programLog.debug("Parameter node: {}".format(parm_node))
            parm_value = parm_node.getVal()
            self.programLog.debug("Parameter value: {}".format(parm_value))
            if isinstance(parm_value, GenericAddress):
                parm_value = parm_value.offset
            parms[i] = parm_value
            if parm_value:
                self.programLog.debug("Parameter {} value: {}".format(i, hex(parm_value)))
        return parms

    def get_call_parm_value(self, call_address):
        parms_value = {}
        if call_address not in self.pcodes_called:
            return

        parms = self.analyzeCallParms(call_address)
        if not parms:
            return

        for i, parm in parms.items():
            self.programLog.debug("Parameter {}: {}".format(i, parms[i]))
            parm_value = parms[i]
            self.programLog.debug("Parameter value: {}".format(parm_value))
            parm_data = None
            if parm_value:
                if is_address_in_current_program(toAddr(parm_value)):
                    if getDataAt(toAddr(parm_value)):
                        parm_data = getDataAt(toAddr(parm_value))
                    elif getInstructionAt(toAddr(parm_value)):
                        parm_data = getFunctionAt(toAddr(parm_value))

            parms_value["parm_{}".format(i)] = {'parm_value': parm_value,
                                                'parm_data': parm_data
                                                }

        return parms_value


# HERE

def dump_call_parm_value(call_address, search_functions=None):
    target_function = getFunctionAt(call_address)
    parms_data = {}

    if not target_function:
        return parms_data

    target_references = getReferencesTo(target_function.getEntryPoint())
    for target_reference in target_references:
        reference_type = target_reference.getReferenceType()
        programLog.debug("Reference Type: {}".format(reference_type))

        if not reference_type.isCall():
            programLog.debug("Skipping non-call reference.")
            continue

        call_addr = target_reference.getFromAddress()
        programLog.debug("Call Address: {}".format(call_addr))

        function = getFunctionContaining(call_addr)
        programLog.debug("Function: {}".format(function))

        if not function or (search_functions and function.name not in search_functions):
            continue

        function_address = function.getEntryPoint()
        if function_address in func_cache:
            target = func_cache[function_address]
        else:
            target = funcAnalysis(function=function)
            func_cache[function_address] = target

        parms_data[call_addr] = {
            'call_addr': call_addr,
            'reference_function_addr': function.getEntryPoint(),
            'reference_function_name': function.name,
            'parms': target.get_call_parm_value(call_address=call_addr) or {}
        }

    return parms_data


# HERE
def main():
    search_functions = None
    function_address = askLong("Input function address to trace", "Please input the function address")
    target_function = getFunctionAt(toAddr(function_address))

    if target_function:
        print_trace_results(target_function, search_functions)
    else:
        print("Can't find function at address: {:#010x}".format(function_address))


def print_trace_results(target_function, search_functions):
    parms_data = dump_call_parm_value(target_function.getEntryPoint(), search_functions)

    for call_addr, call_parms in parms_data.items():
        parm_data_string = create_parm_data_string(call_parms['parms'])
        print_result(target_function, call_parms, call_addr, parm_data_string)


def create_parm_data_string(call_parms):
    parm_data_string = ""
    for parm in sorted(call_parms.keys()):
        parm_value = call_parms[parm]['parm_value']
        parm_data = call_parms[parm]['parm_data']
        if parm_value:
            parm_data_string += "{}({:#010x}), ".format(parm_data, parm_value)
        else:
            parm_data_string += "{}({}), ".format(parm_data, parm_value)
    return parm_data_string.strip(', ')


def print_result(target_function, call_parms, call_addr, parm_data_string):
    print("{}({}) at {:#010x} in {}({:#010x})".format(
        target_function.name,
        parm_data_string,
        call_addr.offset,
        call_parms['reference_function_name'],
        call_parms['reference_function_addr'].offset
    ))


if __name__ == '__main__':
    main()