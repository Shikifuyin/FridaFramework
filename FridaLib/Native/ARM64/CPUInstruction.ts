////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM64/CPUInstruction.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUInstruction for ARM64 Architecture
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

    OperandShifter,
    OperandExtender,
    OperandVAS,

    OperandImmediate,
    OperandRegister,
    OperandMemory,
    OperandFP,
    OperandCImm,
    OperandMRSReg,
    OperandMSRReg,
    OperandPState,
    OperandSys,
    OperandPrefetch,
    OperandBarrier,
    Operand,

    CPUInstruction
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 Instruction Operands
enum OperandType {
    Immediate = 'imm',
    Register  = 'reg',
    Memory    = 'mem',
    FP        = 'fp',
    CImm      = 'cimm',
    MRSReg    = 'reg-mrs',
    MSRReg    = 'reg-msr',
    PState    = 'pstate',
    Sys       = 'sys',
    Prefetch  = 'prefetch',
    Barrier   = 'barrier',
};

enum OperandShifter {
    LSL = 'lsl',
    MSL = 'msl',
    LSR = 'lsr',
    ASR = 'asr',
    ROR = 'ror',
};
enum OperandExtender {
    UXTB = 'uxtb',
    UXTH = 'uxth',
    UXTW = 'uxtw',
    UXTX = 'uxtx',
    SXTB = 'sxtb',
    SXTH = 'sxth',
    SXTW = 'sxtw',
    SXTX = 'sxtx',
};
enum OperandVAS {
    B8  = '8b',
    B16 = '16b',
    H4  = '4h',
    H8  = '8h',
    S2  = '2s',
    S4  = '4s',
    D1  = '1d',
    D2  = '2d',
    Q1  = '1q'
};

interface BaseOperand {
    Type:OperandType;
    Shifter?: {
        Type:OperandShifter;
        Value:number;
    };
    Extender?:OperandExtender;
    VAS?:OperandVAS;
    VectorIndex?:number;
}
interface OperandImmediate extends BaseOperand {
    Value:Integer64;
}
interface OperandRegister extends BaseOperand {
    Value:Register;
}
interface OperandMemory extends BaseOperand {
    Value:{
        Base?:Register;
        Index?:Register;
        Disp:number;
    };
}
interface OperandFP extends BaseOperand {
    Value:number;
}
interface OperandCImm extends BaseOperand {
    Value:Integer64;
}
interface OperandMRSReg extends BaseOperand {
    Value:Register;
}
interface OperandMSRReg extends BaseOperand {
    Value:Register;
}
interface OperandPState extends BaseOperand {
    Value:number;
}
interface OperandSys extends BaseOperand {
    Value:number;
}
interface OperandPrefetch extends BaseOperand {
    Value:number;
}
interface OperandBarrier extends BaseOperand {
    Value:number;
}

type Operand = OperandImmediate | OperandRegister | OperandMemory |
               OperandFP | OperandCImm | OperandMRSReg | OperandMSRReg | OperandPState |
               OperandSys | OperandPrefetch | OperandBarrier;

function _ConvertTo_Operand( hOperand:Arm64Operand ):Operand {
    let hConverted:Partial<Operand> = {};
    hConverted.Type = OperandType[hOperand.type as keyof typeof OperandType];
    hConverted.Shifter = undefined;
    if ( hOperand.shift != undefined ) {
        hConverted.Shifter = {
            Type: OperandShifter[hOperand.shift.type as keyof typeof OperandShifter],
            Value: hOperand.shift.value
        };
    }
    hConverted.Extender = OperandExtender[hOperand.ext as keyof typeof OperandExtender];
    hConverted.VAS = OperandVAS[hOperand.vas as keyof typeof OperandVAS];
    hConverted.VectorIndex = hOperand.vectorIndex;

    switch( hOperand.type ) {
        case OperandType.Immediate:
            hConverted.Value = new Integer64( hOperand.value );
            break;
        case OperandType.Register:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
        case OperandType.Memory:
            hConverted.Value = {
                Base: Register[hOperand.value.base as keyof typeof Register],
                Index: Register[hOperand.value.index as keyof typeof Register],
                Disp: hOperand.value.disp
            };
            break;
        case OperandType.FP:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.CImm:
            hConverted.Value = new Integer64( hOperand.value );
            break;
        case OperandType.MRSReg:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
        case OperandType.MSRReg:
            hConverted.Value = Register[hOperand.value as keyof typeof Register];
            break;
        case OperandType.PState:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.Sys:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.Prefetch:
            hConverted.Value = hOperand.value;
            break;
        case OperandType.Barrier:
            hConverted.Value = hOperand.value;
            break;
    }

    return ( hConverted as Operand );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 Instructions
class CPUInstruction extends BaseCPUInstruction
{
	// Constructor
    constructor( hInstruction:Arm64Instruction )      { super(hInstruction); }
    static Parse( ptrAddress:Pointer ):CPUInstruction { return new CPUInstruction( Instruction.parse(ptrAddress.Handle) as Arm64Instruction ); }

    // Operands
    GetOperandCount():number {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        return instrARM64.operands.length;
    }
    GetOperand( iIndex:number ):Operand {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        assert( iIndex < instrARM64.operands.length );
        return _ConvertTo_Operand( instrARM64.operands[iIndex] );
    }

    // Registers accessed
	GetRegisterReadCount():number {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        return instrARM64.regsRead.length;
    }
	GetRegisterRead( iIndex:number ):Register {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        assert( iIndex < instrARM64.regsRead.length );
        return Register[instrARM64.regsRead[iIndex] as keyof typeof Register];
    }

	GetRegisterWrittenCount():number {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        return instrARM64.regsWritten.length;
    }
	GetRegisterWritten( iIndex:number ):Register {
        let instrARM64:Arm64Instruction = (this.m_hInstruction as Arm64Instruction);
        assert( iIndex < instrARM64.regsWritten.length );
        return Register[instrARM64.regsWritten[iIndex] as keyof typeof Register];
    }
}
