////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM64/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext for ARM64 Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Pointer";
import { BaseCPUContext } from "../CPUContext";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    Register,

    Context,
    _ConvertFrom_Context,
    _ConvertTo_Context
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 Registers
enum Register {
    SP = 'sp', LR = 'lr', FP = 'fp', WSP = 'wsp', WZR = 'wzr', XZR = 'xzr', NZCV = 'nzcv', IP0='ip0', IP1='ip1',

    X0 = 'x0', X1 = 'x1', X2 = 'x2', X3 = 'x3', X4 = 'x4', X5 = 'x5', X6 = 'x6', X7 = 'x7',
    X8 = 'x8', X9 = 'x9', X10 = 'x10', X11 = 'x11', X12 = 'x12', X13 = 'x13', X14 = 'x14', X15 = 'x15',
    X16 = 'x16', X17 = 'x17', X18 = 'x18', X19 = 'x19', X20 = 'x20', X21 = 'x21', X22 = 'x22', X23 = 'x23',
    X24 = 'x24', X25 = 'x25', X26 = 'x26', X27 = 'x27', X28 = 'x28', X29 = 'x29', X30 = 'x30',

    W0 = 'w0', W1 = 'w1', W2 = 'w2', W3 = 'w3', W4 = 'w4', W5 = 'w5', W6 = 'w6', W7 = 'w7',
    W8 = 'w8', W9 = 'w9', W10 = 'w10', W11 = 'w11', W12 = 'w12', W13 = 'w13', W14 = 'w14', W15 = 'w15',
    W16 = 'w16', W17 = 'w17', W18 = 'w18', W19 = 'w19', W20 = 'w20', W21 = 'w21', W22 = 'w22', W23 = 'w23',
    W24 = 'w24', W25 = 'w25', W26 = 'w26', W27 = 'w27', W28 = 'w28', W29 = 'w29', W30 = 'w30',

    S0 = 's0', S1 = 's1', S2 = 's2', S3 = 's3', S4 = 's4', S5 = 's5', S6 = 's6', S7 = 's7',
    S8 = 's8', S9 = 's9', S10 = 's10', S11 = 's11', S12 = 's12', S13 = 's13', S14 = 's14', S15 = 's15',
    S16 = 's16', S17 = 's17', S18 = 's18', S19 = 's19', S20 = 's20', S21 = 's21', S22 = 's22', S23 = 's23',
    S24 = 's24', S25 = 's25', S26 = 's26', S27 = 's27', S28 = 's28', S29 = 's29', S30 = 's30', S31 = 's31',

    D0 = 'd0', D1 = 'd1', D2 = 'd2', D3 = 'd3', D4 = 'd4', D5 = 'd5', D6 = 'd6', D7 = 'd7',
    D8 = 'd8', D9 = 'd9', D10 = 'd10', D11 = 'd11', D12 = 'd12', D13 = 'd13', D14 = 'd14', D15 = 'd15',
    D16 = 'd16', D17 = 'd17', D18 = 'd18', D19 = 'd19', D20 = 'd20', D21 = 'd21', D22 = 'd22', D23 = 'd23',
    D24 = 'd24', D25 = 'd25', D26 = 'd26', D27 = 'd27', D28 = 'd28', D29 = 'd29', D30 = 'd30', D31 = 'd31',

    Q0 = 'q0', Q1 = 'q1', Q2 = 'q2', Q3 = 'q3', Q4 = 'q4', Q5 = 'q5', Q6 = 'q6', Q7 = 'q7',
    Q8 = 'q8', Q9 = 'q9', Q10 = 'q10', Q11 = 'q11', Q12 = 'q12', Q13 = 'q13', Q14 = 'q14', Q15 = 'q15',
    Q16 = 'q16', Q17 = 'q17', Q18 = 'q18', Q19 = 'q19', Q20 = 'q20', Q21 = 'q21', Q22 = 'q22', Q23 = 'q23',
    Q24 = 'q24', Q25 = 'q25', Q26 = 'q26', Q27 = 'q27', Q28 = 'q28', Q29 = 'q29', Q30 = 'q30', Q31 = 'q31'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 Context
interface Context extends BaseCPUContext {
    x0:Pointer;
    x1:Pointer;
    x2:Pointer;
    x3:Pointer;
    x4:Pointer;
    x5:Pointer;
    x6:Pointer;
    x7:Pointer;
    x8:Pointer;
    x9:Pointer;
    x10:Pointer;
    x11:Pointer;
    x12:Pointer;
    x13:Pointer;
    x14:Pointer;
    x15:Pointer;
    x16:Pointer;
    x17:Pointer;
    x18:Pointer;
    x19:Pointer;
    x20:Pointer;
    x21:Pointer;
    x22:Pointer;
    x23:Pointer;
    x24:Pointer;
    x25:Pointer;
    x26:Pointer;
    x27:Pointer;
    x28:Pointer;

    fp:Pointer;
    lr:Pointer;
}

function _ConvertFrom_Context( arm64Context:Context ):Arm64CpuContext {
    let hConverted:Arm64CpuContext = {
        pc: arm64Context.pc.Handle,
        sp: arm64Context.sp.Handle,

        x0: arm64Context.x0.Handle,
        x1: arm64Context.x1.Handle,
        x2: arm64Context.x2.Handle,
        x3: arm64Context.x3.Handle,
        x4: arm64Context.x4.Handle,
        x5: arm64Context.x5.Handle,
        x6: arm64Context.x6.Handle,
        x7: arm64Context.x7.Handle,
        x8: arm64Context.x8.Handle,
        x9: arm64Context.x9.Handle,
        x10: arm64Context.x10.Handle,
        x11: arm64Context.x11.Handle,
        x12: arm64Context.x12.Handle,
        x13: arm64Context.x13.Handle,
        x14: arm64Context.x14.Handle,
        x15: arm64Context.x15.Handle,
        x16: arm64Context.x16.Handle,
        x17: arm64Context.x17.Handle,
        x18: arm64Context.x18.Handle,
        x19: arm64Context.x19.Handle,
        x20: arm64Context.x20.Handle,
        x21: arm64Context.x21.Handle,
        x22: arm64Context.x22.Handle,
        x23: arm64Context.x23.Handle,
        x24: arm64Context.x24.Handle,
        x25: arm64Context.x25.Handle,
        x26: arm64Context.x26.Handle,
        x27: arm64Context.x27.Handle,
        x28: arm64Context.x28.Handle,

        fp: arm64Context.fp.Handle,
        lr: arm64Context.lr.Handle
    };
    return hConverted;
}
function _ConvertTo_Context( arm64Context:Arm64CpuContext ):Context {
    let hConverted:Context = {
        pc: new Pointer( arm64Context.pc ),
        sp: new Pointer( arm64Context.sp ),

        x0: new Pointer( arm64Context.x0 ),
        x1: new Pointer( arm64Context.x1 ),
        x2: new Pointer( arm64Context.x2 ),
        x3: new Pointer( arm64Context.x3 ),
        x4: new Pointer( arm64Context.x4 ),
        x5: new Pointer( arm64Context.x5 ),
        x6: new Pointer( arm64Context.x6 ),
        x7: new Pointer( arm64Context.x7 ),
        x8: new Pointer( arm64Context.x8 ),
        x9: new Pointer( arm64Context.x9 ),
        x10: new Pointer( arm64Context.x10 ),
        x11: new Pointer( arm64Context.x11 ),
        x12: new Pointer( arm64Context.x12 ),
        x13: new Pointer( arm64Context.x13 ),
        x14: new Pointer( arm64Context.x14 ),
        x15: new Pointer( arm64Context.x15 ),
        x16: new Pointer( arm64Context.x16 ),
        x17: new Pointer( arm64Context.x17 ),
        x18: new Pointer( arm64Context.x18 ),
        x19: new Pointer( arm64Context.x19 ),
        x20: new Pointer( arm64Context.x20 ),
        x21: new Pointer( arm64Context.x21 ),
        x22: new Pointer( arm64Context.x22 ),
        x23: new Pointer( arm64Context.x23 ),
        x24: new Pointer( arm64Context.x24 ),
        x25: new Pointer( arm64Context.x25 ),
        x26: new Pointer( arm64Context.x26 ),
        x27: new Pointer( arm64Context.x27 ),
        x28: new Pointer( arm64Context.x28 ),

        fp: new Pointer( arm64Context.fp ),
        lr: new Pointer( arm64Context.lr )
    };
    return hConverted;
}
