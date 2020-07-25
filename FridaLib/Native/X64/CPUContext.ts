////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/X64/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext for X64 Architecture
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
// X64 Registers
enum Register {
    XAX = 'xax', XBX = 'xbx', XCX = 'xcx', XDX = 'xdx', XSI = 'xsi', XDI = 'xdi',
    XSP = 'xsp', XBP = 'xbp', XIP = 'xip',

    RAX = 'rax', RBX = 'rbx', RCX = 'rcx', RDX = 'rdx', RSI = 'rsi', RDI = 'rdi',
    RSP = 'rsp', RBP = 'rbp', RIP = 'rip',

    EAX = 'eax', EBX = 'ebx', ECX = 'ecx', EDX = 'edx', ESI = 'esi', EDI = 'edi',
    ESP = 'esp', EBP = 'ebp', EIP = 'eip',

    R8 = 'r8', R9 = 'r9', R10 = 'r10', R11 = 'r11', R12 = 'r12', R13 = 'r13', R14 = 'r14', R15 = 'r15',
    R8D = 'r8d', R9D = 'r9d', R10D = 'r10d', R11D = 'r11d', R12D = 'r12d', R13D = 'r13d', R14D = 'r14d', R15D = 'r15d'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X64 Context
interface Context extends BaseCPUContext {
    rax:Pointer;
    rbx:Pointer;
    rcx:Pointer;
    rdx:Pointer;
    rsi:Pointer;
    rdi:Pointer;

    rsp:Pointer;
    rbp:Pointer;

    rip:Pointer;

    r8:Pointer;
    r9:Pointer;
    r10:Pointer;
    r11:Pointer;
    r12:Pointer;
    r13:Pointer;
    r14:Pointer;
    r15:Pointer;
}

function _ConvertFrom_Context( x64Context:Context ):X64CpuContext {
    let hConverted:X64CpuContext = {
        pc: x64Context.pc.Handle,
        sp: x64Context.sp.Handle,

        rax: x64Context.rax.Handle,
        rbx: x64Context.rbx.Handle,
        rcx: x64Context.rcx.Handle,
        rdx: x64Context.rdx.Handle,
        rsi: x64Context.rsi.Handle,
        rdi: x64Context.rdi.Handle,

        rsp: x64Context.rsp.Handle,
        rbp: x64Context.rbp.Handle,

        rip: x64Context.rip.Handle,

        r8: x64Context.r8.Handle,
        r9: x64Context.r9.Handle,
        r10: x64Context.r10.Handle,
        r11: x64Context.r11.Handle,
        r12: x64Context.r12.Handle,
        r13: x64Context.r13.Handle,
        r14: x64Context.r14.Handle,
        r15: x64Context.r15.Handle
    };
    return hConverted;
}
function _ConvertTo_Context( x64Context:X64CpuContext ):Context {
    let hConverted:Context = {
        pc: new Pointer( x64Context.pc ),
        sp: new Pointer( x64Context.sp ),

        rax: new Pointer( x64Context.rax ),
        rbx: new Pointer( x64Context.rbx ),
        rcx: new Pointer( x64Context.rcx ),
        rdx: new Pointer( x64Context.rdx ),
        rsi: new Pointer( x64Context.rsi ),
        rdi: new Pointer( x64Context.rdi ),

        rsp: new Pointer( x64Context.rsp ),
        rbp: new Pointer( x64Context.rbp ),

        rip: new Pointer( x64Context.rip ),

        r8: new Pointer( x64Context.r8 ),
        r9: new Pointer( x64Context.r9 ),
        r10: new Pointer( x64Context.r10 ),
        r11: new Pointer( x64Context.r11 ),
        r12: new Pointer( x64Context.r12 ),
        r13: new Pointer( x64Context.r13 ),
        r14: new Pointer( x64Context.r14 ),
        r15: new Pointer( x64Context.r15 )
    };
    return hConverted;
}

