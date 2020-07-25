////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM/CPUInstruction.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUInstruction for ARM Architecture
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

    OperandShifter,

    OperandImmediate,
    OperandRegister,
    OperandMemory,
    OperandFP,
    OperandCImm,
    OperandPImm,
    OperandSetEnd,
    OperandSysReg,
    Operand,

    CPUInstruction
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CPUInstruction Interfaces : Operands
enum OperandType {
    Immediate = 'imm',
    Register  = 'reg',
    Memory    = 'mem',
    FP        = 'fp',
    CImm      = 'cimm',
    PImm      = 'pimm',
    SetEnd    = 'setend',
    SysReg    = 'sysreg'
};

enum OperandShifter {
    ASR = 'asr', LSL = 'lsl', LSR = 'lsr', ROR = 'ror', RRX = 'rrx',
    RegASR = 'asr-reg', RegLSL = 'lsl-reg', RegLSR = 'lsr-reg', RegROR = 'ror-reg', RegRRX = 'rrx-reg'
};
enum OperandEndianness {
    BigEndian    = 'be', // MSB first
    LittleEndian = 'le'  // LSB first
};

interface BaseOperand {
    Type:OperandType;
    Shifter?: {
        Type:OperandShifter;
        Value:number;
    };
    VectorIndex?:number;
    Subtracted:boolean;
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
        Index?:Register;
        Scale:number;
        Disp:number;
    };
}
interface OperandFP extends BaseOperand {
    Value:number;
}
interface OperandCImm extends BaseOperand {
    Value:number;
}
interface OperandPImm extends BaseOperand {
    Value:number;
}
interface OperandSetEnd extends BaseOperand {
    Value:OperandEndianness;
}
interface OperandSysReg extends BaseOperand {
    Value:Register;
}

type Operand = OperandImmediate | OperandRegister | OperandMemory |
               OperandFP | OperandCImm | OperandPImm | OperandSetEnd | OperandSysReg;

function _ConvertTo_Operand( hOperand:ArmOperand ):Operand {
    let hConverted:Partial<Operand> = {};
    hConverted.Type = OperandType[hOperand.type as keyof typeof OperandType];
    hConverted.Shifter = undefined;
    if ( hOperand.shift != undefined ) {
        hConverted.Shifter = {
            Type: OperandShifter[hOperand.shift.type as keyof typeof OperandShifter],
            Value: hOperand.shift.value
        };
    }
    hConverted.VectorIndex = hOperand.vectorIndex;
    hConverted.Subtracted = hOperand.subtracted;

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
                Index: Register[hOperand.value.index as keyof typeof Register],
                Scale: hOperand.value.scale,
                Disp: hOperand.value.disp
            };
            break;
        case OperandType.FP:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.CImm:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.PImm:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.SetEnd:
            hConverted.Value = OperandEndianness[hOperand.value as keyof typeof OperandEndianness];
            break;
        case OperandType.SysReg:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
    }

    return ( hConverted as Operand );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM Instructions
class CPUInstruction extends BaseCPUInstruction
{
	// Constructor
    constructor( hInstruction:ArmInstruction )        { super(hInstruction); }
    static Parse( ptrAddress:Pointer ):CPUInstruction { return new CPUInstruction( Instruction.parse(ptrAddress.Handle) as ArmInstruction ); }

    // Operands
    GetOperandCount():number {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        return instrARM.operands.length;
    }
    GetOperand( iIndex:number ):Operand {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        assert( iIndex < instrARM.operands.length );
        return _ConvertTo_Operand( instrARM.operands[iIndex] );
    }

    // Registers accessed
	GetRegisterReadCount():number {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        return instrARM.regsRead.length;
    }
	GetRegisterRead( iIndex:number ):Register {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        assert( iIndex < instrARM.regsRead.length );
        return Register[instrARM.regsRead[iIndex] as keyof typeof Register];
    }

	GetRegisterWrittenCount():number {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        return instrARM.regsWritten.length;
    }
	GetRegisterWritten( iIndex:number ):Register {
        let instrARM:ArmInstruction = (this.m_hInstruction as ArmInstruction);
        assert( iIndex < instrARM.regsWritten.length );
        return Register[instrARM.regsWritten[iIndex] as keyof typeof Register];
    }
}
