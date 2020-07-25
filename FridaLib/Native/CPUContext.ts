////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext common to all Architectures
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "./Pointer"

import * as X86 from "./X86/CPUContext"
import * as X64 from "./X64/CPUContext"
import * as ARM from "./ARM/CPUContext"
import * as ARM64 from "./ARM64/CPUContext"
import * as MIPS from "./MIPS/CPUContext"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    BaseCPUContext,
    CPUContext,
    _ConvertFrom_CPUContext,
    _ConvertTo_CPUContext
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CPUContext Interface
interface BaseCPUContext {
    pc:Pointer; // Program counter
    sp:Pointer; // Stack Pointer
}

type CPUContext = BaseCPUContext | X86.Context | X64.Context | ARM.Context | ARM64.Context | MIPS.Context;

function _ConvertFrom_CPUContext( hContext:CPUContext ):CpuContext {
    if ( (hContext as X86.Context).eax != undefined )  return X86._ConvertFrom_Context( hContext as X86.Context );
    if ( (hContext as X64.Context).rax != undefined )  return X64._ConvertFrom_Context( hContext as X64.Context );
    if ( (hContext as ARM.Context).r0 != undefined )   return ARM._ConvertFrom_Context( hContext as ARM.Context );
    if ( (hContext as ARM64.Context).x0 != undefined ) return ARM64._ConvertFrom_Context( hContext as ARM64.Context );
    return MIPS._ConvertFrom_Context( hContext as MIPS.Context );
}
function _ConvertTo_CPUContext( hContext:CpuContext ):CPUContext {
    if ( (hContext as Ia32CpuContext).eax != undefined ) return X86._ConvertTo_Context( hContext as Ia32CpuContext );
    if ( (hContext as X64CpuContext).rax != undefined )  return X64._ConvertTo_Context( hContext as X64CpuContext );
    if ( (hContext as ArmCpuContext).r0 != undefined )   return ARM._ConvertTo_Context( hContext as ArmCpuContext );
    if ( (hContext as Arm64CpuContext).x0 != undefined ) return ARM64._ConvertTo_Context( hContext as Arm64CpuContext );
    return MIPS._ConvertTo_Context( hContext as MipsCpuContext );
}

