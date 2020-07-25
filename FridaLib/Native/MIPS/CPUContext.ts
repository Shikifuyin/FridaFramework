////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/MIPS/CPUContext.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUContext for MIPS Architecture
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
// MIPS Registers
enum Register {
    GP = 'gp', SP = 'sp', FP = 'fp', RA = 'ra', HI = 'hi', LO = 'lo', ZERO = 'zero', AT = 'at',

    V0 = 'v0', V1 = 'v1',
    K0 = 'k0', K1 = 'k1',

    A0 = 'a0', A1 = 'a1', A2 = 'a2', A3 = 'a3',

    T0 = 't0', T1 = 't1', T2 = 't2', T3 = 't3', T4 = 't4', T5 = 't5', T6 = 't6', T7 = 't7', T8 = 't8', T9 = 't9',
    S0 = 's0', S1 = 's1', S2 = 's2', S3 = 's3', S4 = 's4', S5 = 's5', S6 = 'st6', S7 = 's7', S8 = 's8',

    _0 = '0', _1 = '1', _2 = '2', _3 = '3', _4 = '4', _5 = '5', _6 = '6', _7 = '7',
    _8 = '8', _9 = '9', _10 = '10', _11 = '11', _12 = '12', _13 = '13', _14 = '14', _15 = '15',
    _16 = '16', _17 = '17', _18 = '18', _19 = '19', _20 = '20', _21 = '21', _22 = '22', _23 = '23',
    _24 = '24', _25 = '25', _26 = '26', _27 = '27', _28 = '28', _29 = '29', _30 = '30', _31 = '31'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// MIPS Context
interface Context extends BaseCPUContext {
    gp:Pointer;
    fp:Pointer;
    ra:Pointer;

    hi:Pointer;
    lo:Pointer;

    at:Pointer;

    v0:Pointer;
    v1:Pointer;

    a0:Pointer;
    a1:Pointer;
    a2:Pointer;
    a3:Pointer;

    t0:Pointer;
    t1:Pointer;
    t2:Pointer;
    t3:Pointer;
    t4:Pointer;
    t5:Pointer;
    t6:Pointer;
    t7:Pointer;
    t8:Pointer;
    t9:Pointer;

    s0:Pointer;
    s1:Pointer;
    s2:Pointer;
    s3:Pointer;
    s4:Pointer;
    s5:Pointer;
    s6:Pointer;
    s7:Pointer;

    k0:Pointer;
    k1:Pointer;
}

function _ConvertFrom_Context( mipsContext:Context ):MipsCpuContext {
    let hConverted:MipsCpuContext = {
        pc: mipsContext.pc.Handle,
        sp: mipsContext.sp.Handle,

        gp: mipsContext.gp.Handle,
        fp: mipsContext.fp.Handle,
        ra: mipsContext.ra.Handle,
    
        hi: mipsContext.hi.Handle,
        lo: mipsContext.lo.Handle,
    
        at: mipsContext.at.Handle,
    
        v0: mipsContext.v0.Handle,
        v1: mipsContext.v1.Handle,
    
        a0: mipsContext.a0.Handle,
        a1: mipsContext.a1.Handle,
        a2: mipsContext.a2.Handle,
        a3: mipsContext.a3.Handle,
    
        t0: mipsContext.t0.Handle,
        t1: mipsContext.t1.Handle,
        t2: mipsContext.t2.Handle,
        t3: mipsContext.t3.Handle,
        t4: mipsContext.t4.Handle,
        t5: mipsContext.t5.Handle,
        t6: mipsContext.t6.Handle,
        t7: mipsContext.t7.Handle,
        t8: mipsContext.t8.Handle,
        t9: mipsContext.t9.Handle,
    
        s0: mipsContext.s0.Handle,
        s1: mipsContext.s1.Handle,
        s2: mipsContext.s2.Handle,
        s3: mipsContext.s3.Handle,
        s4: mipsContext.s4.Handle,
        s5: mipsContext.s5.Handle,
        s6: mipsContext.s6.Handle,
        s7: mipsContext.s7.Handle,
    
        k0: mipsContext.k0.Handle,
        k1: mipsContext.k1.Handle
    };
    return hConverted;
}
function _ConvertTo_Context( mipsContext:MipsCpuContext ):Context {
    let hConverted:Context = {
        pc: new Pointer( mipsContext.pc ),
        sp: new Pointer( mipsContext.sp ),

        gp: new Pointer( mipsContext.gp ),
        fp: new Pointer( mipsContext.fp ),
        ra: new Pointer( mipsContext.ra ),
    
        hi: new Pointer( mipsContext.hi ),
        lo: new Pointer( mipsContext.lo ),
    
        at: new Pointer( mipsContext.at ),
    
        v0: new Pointer( mipsContext.v0 ),
        v1: new Pointer( mipsContext.v1 ),
    
        a0: new Pointer( mipsContext.a0 ),
        a1: new Pointer( mipsContext.a1 ),
        a2: new Pointer( mipsContext.a2 ),
        a3: new Pointer( mipsContext.a3 ),
    
        t0: new Pointer( mipsContext.t0 ),
        t1: new Pointer( mipsContext.t1 ),
        t2: new Pointer( mipsContext.t2 ),
        t3: new Pointer( mipsContext.t3 ),
        t4: new Pointer( mipsContext.t4 ),
        t5: new Pointer( mipsContext.t5 ),
        t6: new Pointer( mipsContext.t6 ),
        t7: new Pointer( mipsContext.t7 ),
        t8: new Pointer( mipsContext.t8 ),
        t9: new Pointer( mipsContext.t9 ),
    
        s0: new Pointer( mipsContext.s0 ),
        s1: new Pointer( mipsContext.s1 ),
        s2: new Pointer( mipsContext.s2 ),
        s3: new Pointer( mipsContext.s3 ),
        s4: new Pointer( mipsContext.s4 ),
        s5: new Pointer( mipsContext.s5 ),
        s6: new Pointer( mipsContext.s6 ),
        s7: new Pointer( mipsContext.s7 ),
    
        k0: new Pointer( mipsContext.k0 ),
        k1: new Pointer( mipsContext.k1 )
    };
    return hConverted;
}
