////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/X86/CPUInstruction.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUInstruction for X86 Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { assert } from "console";

import { Integer64 } from "../Integer64";
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
// CPUInstruction Interfaces : Operands
enum OperandType {
    Immediate = 'imm',
    Register  = 'reg',
    Memory    = 'mem'
};

interface BaseOperand {
    Type:OperandType;
    Size:number;
}
interface OperandImmediate extends BaseOperand {
    Value:number | Integer64;
}
interface OperandRegister extends BaseOperand {
    Value:Register;
}
interface OperandMemory extends BaseOperand {
    Value:{
        Segment?:Register;
        Base?:Register;
        Index?:Register;
        Scale:number;
        Disp:number;
    };
}

type Operand = OperandImmediate | OperandRegister | OperandMemory;

function _ConvertTo_Operand( hOperand:X86Operand ):Operand {
    let hConverted:Partial<Operand> = {};
    hConverted.Type = OperandType[hOperand.type as keyof typeof OperandType];
    hConverted.Size = hOperand.size;
    
    switch( hOperand.type ) {
        case OperandType.Immediate:
            hConverted.Value = (hOperand.value instanceof Int64) ? new Integer64(hOperand.value) : hOperand.value;
            break;
        case OperandType.Register:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
        case OperandType.Memory:
            hConverted.Value = {
                Segment: Register[hOperand.value.segment as keyof typeof Register],
                Base: Register[hOperand.value.base as keyof typeof Register],
                Index: Register[hOperand.value.index as keyof typeof Register],
                Scale: hOperand.value.scale,
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
    constructor( hInstruction:X86Instruction )        { super(hInstruction); }
    static Parse( ptrAddress:Pointer ):CPUInstruction { return new CPUInstruction( Instruction.parse(ptrAddress.Handle) as X86Instruction ); }

    // Operands
    GetOperandCount():number {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        return instrX86.operands.length;
    }
    GetOperand( iIndex:number ):Operand {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        assert( iIndex < instrX86.operands.length );
        return _ConvertTo_Operand( instrX86.operands[iIndex] );
    }

    // Registers accessed
	GetRegisterReadCount():number {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        return instrX86.regsRead.length;
    }
	GetRegisterRead( iIndex:number ):Register {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        assert( iIndex < instrX86.regsRead.length );
        return Register[instrX86.regsRead[iIndex] as keyof typeof Register];
    }

	GetRegisterWrittenCount():number {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        return instrX86.regsWritten.length;
    }
	GetRegisterWritten( iIndex:number ):Register {
        let instrX86:X86Instruction = (this.m_hInstruction as X86Instruction);
        assert( iIndex < instrX86.regsWritten.length );
        return Register[instrX86.regsWritten[iIndex] as keyof typeof Register];
    }
}

