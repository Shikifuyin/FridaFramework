////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/MIPS/CPUInstruction.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUInstruction for MIPS Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { assert } from "console";

import { Pointer } from "../Pointer";
import { BaseCPUInstruction } from "../CPUInstruction";

import { Register } from "./CPUContext";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    OperandType,

    OperandImmediate,
    OperandRegister,
    OperandMemory,
    Operand,

    CPUInstruction
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 Instruction Operands
enum OperandType {
    Immediate = 'imm',
    Register  = 'reg',
    Memory    = 'mem'
};

interface BaseOperand {
    Type:OperandType;
}
interface OperandImmediate extends BaseOperand {
    Value:number;
}
interface OperandRegister extends BaseOperand {
    Value:Register;
}
interface OperandMemory extends BaseOperand {
    Value:{
        Base?:Register;
        Disp:number;
    };
}

type Operand = OperandImmediate | OperandRegister | OperandMemory;

function _ConvertTo_Operand( hOperand:MipsOperand ):Operand {
    let hConverted:Partial<Operand> = {};
    hConverted.Type = OperandType[hOperand.type as keyof typeof OperandType];

    switch( hOperand.type ) {
        case OperandType.Immediate:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.Register:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
        case OperandType.Memory:
            hConverted.Value = {
                Base: Register[hOperand.value.base as keyof typeof Register],
                Disp: hOperand.value.disp
            };
            break;
    }

    return ( hConverted as Operand );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 Instructions
class CPUInstruction extends BaseCPUInstruction
{
	// Constructor
    constructor( hInstruction:MipsInstruction )    { super(hInstruction); }
    static Parse( ptrAddress:Pointer ):CPUInstruction { return new CPUInstruction( Instruction.parse(ptrAddress.Handle) as MipsInstruction ); }

    // Operands
    GetOperandCount():number {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        return instrMIPS.operands.length;
    }
    GetOperand( iIndex:number ):Operand {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        assert( iIndex < instrMIPS.operands.length );
        return _ConvertTo_Operand( instrMIPS.operands[iIndex] );
    }

    // Registers accessed
	GetRegisterReadCount():number {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        return instrMIPS.regsRead.length;
    }
	GetRegisterRead( iIndex:number ):Register {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        assert( iIndex < instrMIPS.regsRead.length );
        return Register[instrMIPS.regsRead[iIndex] as keyof typeof Register];
    }

	GetRegisterWrittenCount():number {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        return instrMIPS.regsWritten.length;
    }
	GetRegisterWritten( iIndex:number ):Register {
        let instrMIPS:MipsInstruction = (this.m_hInstruction as MipsInstruction);
        assert( iIndex < instrMIPS.regsWritten.length );
        return Register[instrMIPS.regsWritten[iIndex] as keyof typeof Register];
    }
}

