////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/X86/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext for X86 Architecture
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
// X86 Registers
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
// X86 Context
interface Context extends BaseCPUContext {
    eax:Pointer;
    ebx:Pointer;
    ecx:Pointer;
    edx:Pointer;
    esi:Pointer;
    edi:Pointer;

    esp:Pointer;
    ebp:Pointer;

    eip:Pointer;
}

function _ConvertFrom_Context( x86Context:Context ):Ia32CpuContext {
    let hConverted:Ia32CpuContext = {
        pc: x86Context.pc.Handle,
        sp: x86Context.sp.Handle,

        eax: x86Context.eax.Handle,
        ebx: x86Context.ebx.Handle,
        ecx: x86Context.ecx.Handle,
        edx: x86Context.edx.Handle,
        esi: x86Context.esi.Handle,
        edi: x86Context.edi.Handle,

        esp: x86Context.esp.Handle,
        ebp: x86Context.ebp.Handle,

        eip: x86Context.eip.Handle
    };
    return hConverted;
}
function _ConvertTo_Context( x86Context:Ia32CpuContext ):Context {
    let hConverted:Context = {
        pc: new Pointer( x86Context.pc ),
        sp: new Pointer( x86Context.sp ),

        eax: new Pointer( x86Context.eax ),
        ebx: new Pointer( x86Context.ebx ),
        ecx: new Pointer( x86Context.ecx ),
        edx: new Pointer( x86Context.edx ),
        esi: new Pointer( x86Context.esi ),
        edi: new Pointer( x86Context.edi ),

        esp: new Pointer( x86Context.esp ),
        ebp: new Pointer( x86Context.ebp ),

        eip: new Pointer( x86Context.eip )
    };
    return hConverted;
}

