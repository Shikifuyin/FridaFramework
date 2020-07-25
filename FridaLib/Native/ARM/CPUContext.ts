////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext for ARM Architecture
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
// ARM Registers
enum Register {
    SP = 'sp', LR = 'lr', SB = 'sb', SL = 'sl', FP = 'fp', IP='ip', PC = 'pc',

    R0 = 'r0', R1 = 'r1', R2 = 'r2', R3 = 'r3', R4 = 'r4', R5 = 'r5', R6 = 'r6', R7 = 'r7',
    R8 = 'r8', R9 = 'r9', R10 = 'r10', R11 = 'r11', R12 = 'r12', R13 = 'r13', R14 = 'r14', R15 = 'r15'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM Context
interface Context extends BaseCPUContext {
    r0:Pointer;
    r1:Pointer;
    r2:Pointer;
    r3:Pointer;
    r4:Pointer;
    r5:Pointer;
    r6:Pointer;
    r7:Pointer;

    r8:Pointer;
    r9:Pointer;
    r10:Pointer;
    r11:Pointer;
    r12:Pointer;

    lr:Pointer;
}

function _ConvertFrom_Context( armContext:Context ):ArmCpuContext {
    let hConverted:ArmCpuContext = {
        pc: armContext.pc.Handle,
        sp: armContext.sp.Handle,

        r0: armContext.r0.Handle,
        r1: armContext.r1.Handle,
        r2: armContext.r2.Handle,
        r3: armContext.r3.Handle,
        r4: armContext.r4.Handle,
        r5: armContext.r5.Handle,
        r6: armContext.r6.Handle,
        r7: armContext.r7.Handle,
        r8: armContext.r8.Handle,
        r9: armContext.r9.Handle,
        r10: armContext.r10.Handle,
        r11: armContext.r11.Handle,
        r12: armContext.r12.Handle,

        lr: armContext.lr.Handle
    };
    return hConverted;
}
function _ConvertTo_Context( armContext:ArmCpuContext ):Context {
    let hConverted:Context = {
        pc: new Pointer( armContext.pc ),
        sp: new Pointer( armContext.sp ),

        r0: new Pointer( armContext.r0 ),
        r1: new Pointer( armContext.r1 ),
        r2: new Pointer( armContext.r2 ),
        r3: new Pointer( armContext.r3 ),
        r4: new Pointer( armContext.r4 ),
        r5: new Pointer( armContext.r5 ),
        r6: new Pointer( armContext.r6 ),
        r7: new Pointer( armContext.r7 ),
        r8: new Pointer( armContext.r8 ),
        r9: new Pointer( armContext.r9 ),
        r10: new Pointer( armContext.r10 ),
        r11: new Pointer( armContext.r11 ),
        r12: new Pointer( armContext.r12 ),

        lr: new Pointer( armContext.lr )
    };
    return hConverted;
}
