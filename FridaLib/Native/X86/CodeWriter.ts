////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/X86/CodeWriter.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Writer for X86 Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Integer64 } from "../Integer64";
import { UInteger64 } from "../UInteger64";
import { Pointer } from "../Pointer";

import { Register } from "./CPUContext";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    PtrTarget,

    JmpInstruction,
    BranchHint,

    OffsetPtr,
    CallArgument,

    CodeWriter
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 Pointer Target
enum PtrTarget {
    BytePtr  = 'byte',
    DWordPtr = 'dword',
    QWordPtr = 'qword'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 Jump Instructions
enum JmpInstruction {
    JE = 'je', JNE = 'jne', JB = 'jb', JBE = 'jbe', JA = 'ja', JAE = 'jae',
    JL = 'jl', JLE = 'jle', JG = 'jg', JGE = 'jge', JO = 'jo', JNO = 'jno',
    JP = 'jp', JNP = 'jnp', JS = 'js', JNS = 'jns',
    JCXZ = 'jcxz', JECXZ = 'jecxz', JRCXZ = 'jrcxz'
};

enum BranchHint {
    NoHint   = 'no-hint',
    Likely   = 'likely',
    Unlikely = 'unlikely'
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 CodeWriter Helpers
type OffsetPtr =  number | Integer64 | UInteger64;
type CallArgument =  number | Integer64 | UInteger64 | Pointer | Register;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// X86 CodeWriter
class CodeWriter
{
	// Members
    private m_hX86Writer:X86Writer;
    
    // Helpers
    private static _ConvertOffsetPtr( iOffset:OffsetPtr ):number | Int64 | UInt64 {
        if ( iOffset instanceof Integer64 || iOffset instanceof UInteger64 )
            return iOffset.Handle;
        return iOffset;
    }
    private static _ConvertArguments( arrArguments:CallArgument[] ):X86CallArgument[] {
        let arrArgs:X86CallArgument[] = [];
        arrArguments.forEach( function(hArg:CallArgument):void {
            if ( hArg instanceof Integer64 || hArg instanceof UInteger64 || hArg instanceof Pointer )
                arrArgs.push( hArg.Handle );
            else
                arrArgs.push( hArg );
        });
        return arrArgs;
    }

	// Getter
	get Handle():X86Writer { return this.m_hX86Writer; }

	// Constructor
	constructor( hX86Writer:X86Writer ) {
		this.m_hX86Writer = hX86Writer;
	}
	static Create( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):CodeWriter {
		let hOptions:X86WriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		return new CodeWriter( new X86Writer(ptrCodeAddress.Handle, hOptions) );
    }
    Reset( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):void {
		let hOptions:X86WriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		this.m_hX86Writer.reset( ptrCodeAddress.Handle, hOptions );
	}

	// Properties
	GetBasePointer():Pointer    { return new Pointer( this.m_hX86Writer.base ); }
	GetCodePointer():Pointer    { return new Pointer( this.m_hX86Writer.code ); }
	GetProgramCounter():Pointer { return new Pointer( this.m_hX86Writer.pc ); }
	GetOffset():number          { return this.m_hX86Writer.offset; }

	// Methods
	Cleanup():void { this.m_hX86Writer.dispose(); }
	Flush():void   { this.m_hX86Writer.flush(); }

	// Labels
	PutLabel( strLabel:string ):void { this.m_hX86Writer.putLabel(strLabel); }

	// Raw Code
	PutChar( immValue:number ):void                           { this.m_hX86Writer.putS8(immValue); }
	PutByte( immValue:number ):void                           { this.m_hX86Writer.putU8(immValue); }
	PutBytes( arrBytes:string | number[] | ArrayBuffer ):void { this.m_hX86Writer.putBytes(arrBytes); }

	// NOPs, Padding & Fencing
	NOP():void                    { this.m_hX86Writer.putNop(); }
	NOPs( iCount:number ):void    { this.m_hX86Writer.putNopPadding(iCount); }
	Padding( iCount:number ):void { this.m_hX86Writer.putPadding(iCount); } // guard instructions (breakpoints)

	// Breakpoints
	BreakPoint():void { this.m_hX86Writer.putBreakpoint(); }

	// Spin-Lock de-queue
	Pause():void { this.m_hX86Writer.putPause(); }

	// Serialization & Fencing
	CPUID():void  { this.m_hX86Writer.putCpuid(); }  // Serializing Regs & Memory
	LFence():void { this.m_hX86Writer.putLfence(); } // Memory-Ordering

	// TimeStamp Counter
	RDTSC():void { this.m_hX86Writer.putRdtsc(); }

	// Flags (Carry, Direction)
	STC():void { this.m_hX86Writer.putStc(); }
	CLC():void { this.m_hX86Writer.putClc(); }
	STD():void { this.m_hX86Writer.putStd(); }
	CLD():void { this.m_hX86Writer.putCld(); }

	// Stack
	PushAX():void                          { this.m_hX86Writer.putPushax(); }
	PushFX():void                          { this.m_hX86Writer.putPushfx(); }
	PushReg( strReg:Register ):void        { this.m_hX86Writer.putPushReg(strReg); }
	PushDword( immValue:number ):void      { this.m_hX86Writer.putPushU32(immValue); }
	PushPtrNear( ptrAddress:Pointer ):void { this.m_hX86Writer.putPushNearPtr(ptrAddress.Handle); }
	PushPtrImm( ptrAddress:Pointer ):void  { this.m_hX86Writer.putPushImmPtr(ptrAddress.Handle); }
	
	PopAX():void                   { this.m_hX86Writer.putPopax(); }
	PopFX():void                   { this.m_hX86Writer.putPopfx(); }
	PopReg( strReg:Register ):void { this.m_hX86Writer.putPopReg(strReg); }

	// Jump
	Jmp( ptrAddress:Pointer ):void        { this.m_hX86Writer.putJmpAddress(ptrAddress.Handle); }
	JmpNear( ptrAddress:Pointer ):void    { this.m_hX86Writer.putJmpNearPtr(ptrAddress.Handle); }
	JmpLabelNear( strLabel:string ):void  { this.m_hX86Writer.putJmpNearLabel(strLabel); }
	JmpLabelShort( strLabel:string ):void { this.m_hX86Writer.putJmpShortLabel(strLabel); }
	JmpReg( strReg:Register ):void        { this.m_hX86Writer.putJmpReg(strReg); }
	JmpRegPtr( strReg:Register ):void     { this.m_hX86Writer.putJmpRegPtr(strReg); }
	JmpRegOffsetPtr( strReg:Register, iOffset:OffsetPtr ):void {
        this.m_hX86Writer.putJmpRegOffsetPtr( strReg, CodeWriter._ConvertOffsetPtr(iOffset) );
    }
	
	// Conditional Jump
	JccNear( strJmp:JmpInstruction, ptrAddress:Pointer, strHint:BranchHint = BranchHint.NoHint ):void {
        this.m_hX86Writer.putJccNear( strJmp, ptrAddress.Handle, strHint );
    }
	JccShort( strJmp:JmpInstruction, ptrAddress:Pointer, strHint:BranchHint = BranchHint.NoHint ):void {
        this.m_hX86Writer.putJccShort( strJmp, ptrAddress.Handle, strHint );
    }
	JccLabelNear( strJmp:JmpInstruction, strLabel:string, strHint:BranchHint = BranchHint.NoHint ):void  {
        this.m_hX86Writer.putJccNearLabel( strJmp, strLabel, strHint );
    }
	JccLabelShort( strJmp:JmpInstruction, strLabel:string, strHint:BranchHint = BranchHint.NoHint ):void {
        this.m_hX86Writer.putJccShortLabel( strJmp, strLabel, strHint );
    }

	// Call / Ret
	Call( ptrAddress:Pointer ):void           { this.m_hX86Writer.putCallAddress(ptrAddress.Handle); }
	CallIndirect( ptrAddress:Pointer ):void   { this.m_hX86Writer.putCallIndirect(ptrAddress.Handle); }
	CallLabelNear( strLabel:string ):void     { this.m_hX86Writer.putCallNearLabel(strLabel); }
	CallLabelIndirect( strLabel:string ):void { this.m_hX86Writer.putCallIndirectLabel(strLabel); }
	CallReg( strReg:Register ):void           { this.m_hX86Writer.putCallReg(strReg); }
	CallRegOffsetPtr( strReg:Register, iOffset:OffsetPtr ):void {
        this.m_hX86Writer.putCallRegOffsetPtr( strReg, CodeWriter._ConvertOffsetPtr(iOffset) );
    }

	FCall( ptrFunction:Pointer, arrArguments:CallArgument[] ):void {
        let arrArgs:X86CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hX86Writer.putCallAddressWithArguments( ptrFunction.Handle, arrArgs );
    }
	FCallAligned( ptrFunction:Pointer, arrArguments:CallArgument[] ):void {
        let arrArgs:X86CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hX86Writer.putCallAddressWithAlignedArguments( ptrFunction.Handle, arrArgs );
    }
	FCallReg( strReg:Register, arrArguments:CallArgument[] ):void {
        let arrArgs:X86CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hX86Writer.putCallRegWithArguments( strReg, arrArgs );
    }
	FCallRegAligned( strReg:Register, arrArguments:CallArgument[] ):void {
        let arrArgs:X86CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hX86Writer.putCallRegWithAlignedArguments( strReg, arrArgs );
    }
	FCallRegOffsetPtr( strReg:Register, iOffset:OffsetPtr, arrArguments:CallArgument[] ):void {
        let arrArgs:X86CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hX86Writer.putCallRegOffsetPtrWithArguments( strReg, CodeWriter._ConvertOffsetPtr(iOffset), arrArgs );
    }

	Ret():void                     { this.m_hX86Writer.putRet(); }
	RetImm( immValue:number ):void { this.m_hX86Writer.putRetImm(immValue); }
	Leave():void                   { this.m_hX86Writer.putLeave(); }

	// Mov variants
	MovRegImm( strRegDst:Register, immValue:number ):void {
        this.m_hX86Writer.putMovRegU32( strRegDst, immValue );
    }
	MovRegImm64( strRegDst:Register, immValue:number | UInteger64 ):void {
        this.m_hX86Writer.putMovRegU64( strRegDst, CodeWriter._ConvertOffsetPtr(immValue) );
    }
	MovRegAddress( strRegDst:Register, ptrAddress:Pointer ):void {
        this.m_hX86Writer.putMovRegAddress( strRegDst, ptrAddress.Handle );
    }
    MovRegPtrImm( strRegDst:Register, immValue:number ):void {
        this.m_hX86Writer.putMovRegPtrU32( strRegDst, immValue );
    }

	MovRegReg( strRegDst:Register, strRegSrc:Register ):void    { this.m_hX86Writer.putMovRegReg(strRegDst, strRegSrc); }
	MovRegRegPtr( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putMovRegRegPtr(strRegDst, strRegSrc); }
	MovRegRegOffsetPtr( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hX86Writer.putMovRegRegOffsetPtr( strRegDst, strRegSrc, CodeWriter._ConvertOffsetPtr(iOffsetSrc) );
    }

	MovRegPtrReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putMovRegPtrReg(strRegDst, strRegSrc); }

	MovRegOffsetPtrImm( strRegDst:Register, iOffsetDst:OffsetPtr, immValue:number ):void {
        this.m_hX86Writer.putMovRegOffsetPtrU32( strRegDst, CodeWriter._ConvertOffsetPtr(iOffsetDst), immValue );
    }
	MovRegOffsetPtrReg( strRegDst:Register, iOffsetDst:OffsetPtr, strRegSrc:Register ):void {
        this.m_hX86Writer.putMovRegOffsetPtrReg( strRegDst, CodeWriter._ConvertOffsetPtr(iOffsetDst), strRegSrc );
    }

	MovRegNearPtr( strRegDst:Register, ptrAddress:Pointer ):void { this.m_hX86Writer.putMovRegNearPtr(strRegDst, ptrAddress.Handle); }
	MovNearPtrReg( ptrAddress:Pointer, strRegSrc:Register ):void { this.m_hX86Writer.putMovNearPtrReg(ptrAddress.Handle, strRegSrc); }
	
	MovRegBaseIdxScaleOffsetPtr( strRegDst:Register, strRegBase:Register, strRegIndex:Register, iScale:number, iOffset:OffsetPtr ):void {
		this.m_hX86Writer.putMovRegBaseIndexScaleOffsetPtr( strRegDst, strRegBase, strRegIndex, iScale, CodeWriter._ConvertOffsetPtr(iOffset) );
	}
	
    MovFSRegOffsetPtr( strRegDst:Register, iOffsetSrc:number ):void {
        this.m_hX86Writer.putMovRegFsU32Ptr( strRegDst, iOffsetSrc );
    }
    MovFSOffsetPtrReg( iOffsetDst:number, strRegSrc:Register ):void {
        this.m_hX86Writer.putMovFsU32PtrReg( iOffsetDst, strRegSrc );
    }

    MovGSRegOffsetPtr( strRegDst:Register, iOffsetSrc:number ):void {
        this.m_hX86Writer.putMovRegGsU32Ptr( strRegDst, iOffsetSrc );
    }
    MovGSOffsetPtrReg( iOffsetDst:number, strRegSrc:Register ):void {
        this.m_hX86Writer.putMovGsU32PtrReg( iOffsetDst, strRegSrc );
    }

	MovQXmm0EspOffsetPtr( iOffsetSrc:number ):void { this.m_hX86Writer.putMovqXmm0EspOffsetPtr(iOffsetSrc); }
	MovQEaxOffsetPtrXmm0( iOffsetDst:number ):void { this.m_hX86Writer.putMovqEaxOffsetPtrXmm0(iOffsetDst); }

	MovDQUXmm0EspOffsetPtr( iOffsetSrc:number ):void { this.m_hX86Writer.putMovdquXmm0EspOffsetPtr(iOffsetSrc); }
	MovDQUEaxOffsetPtrXmm0( iOffsetDst:number ):void { this.m_hX86Writer.putMovdquEaxOffsetPtrXmm0(iOffsetDst); }
	
	XChgRegRegPtr( strRegL:Register, strRegR:Register ):void { this.m_hX86Writer.putXchgRegRegPtr(strRegL, strRegR); }

	Lea( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hX86Writer.putLeaRegRegOffset( strRegDst, strRegSrc, CodeWriter._ConvertOffsetPtr(iOffsetSrc) );
    }

	// Arithmetics
	AddRegImm( strReg:Register, immValue:OffsetPtr ):void {
        this.m_hX86Writer.putAddRegImm( strReg, CodeWriter._ConvertOffsetPtr(immValue) );
    }
	AddRegReg( strRegDst:Register, strRegSrc:Register ):void         { this.m_hX86Writer.putAddRegReg(strRegDst, strRegSrc); }
	AddRegNearPtr( strReg:Register, ptrAddress:Pointer ):void        { this.m_hX86Writer.putAddRegNearPtr(strReg, ptrAddress.Handle); }
	XAddRegPtrRegLock( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putLockXaddRegPtrReg(strRegDst, strRegSrc); }

	SubRegImm( strReg:Register, immValue:OffsetPtr ):void     {
        this.m_hX86Writer.putSubRegImm( strReg, CodeWriter._ConvertOffsetPtr(immValue) );
    }
	SubRegReg( strRegDst:Register, strRegSrc:Register ):void  { this.m_hX86Writer.putSubRegReg(strRegDst, strRegSrc); }
	SubRegNearPtr( strReg:Register, ptrAddress:Pointer ):void { this.m_hX86Writer.putSubRegNearPtr(strReg, ptrAddress.Handle); }

	IncReg( strReg:Register ):void                         { this.m_hX86Writer.putIncReg(strReg); }
	IncRegPtr( ptrTarget:PtrTarget, strReg:Register ):void { this.m_hX86Writer.putIncRegPtr(ptrTarget, strReg); }
	IncImmPtrLock( ptrAddress:Pointer ):void               { this.m_hX86Writer.putLockIncImm32Ptr(ptrAddress.Handle); }

	DecReg( strReg:Register ):void                         { this.m_hX86Writer.putDecReg(strReg); }
	DecRegPtr( ptrTarget:PtrTarget, strReg:Register ):void { this.m_hX86Writer.putDecRegPtr(ptrTarget, strReg); }
	DecImmPtrLock( ptrAddress:Pointer ):void               { this.m_hX86Writer.putLockDecImm32Ptr(ptrAddress.Handle); }

	AndRegImm( strReg:Register, immValue:number ):void       { this.m_hX86Writer.putAndRegU32(strReg, immValue); }
	AndRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putAndRegReg(strRegDst, strRegSrc); }

	XorRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putXorRegReg(strRegDst, strRegSrc); }

	ShlRegImm( strReg:Register, immValue:number ):void { this.m_hX86Writer.putShlRegU8(strReg, immValue); }
	ShrRegImm( strReg:Register, immValue:number ):void { this.m_hX86Writer.putShrRegU8(strReg, immValue); }

	// Compare & Test
	CmpRegImm( strReg:Register, immValue:number ):void   { this.m_hX86Writer.putCmpRegI32(strReg, immValue); }
	CmpRegReg( strRegL:Register, strRegR:Register ):void { this.m_hX86Writer.putCmpRegReg(strRegL, strRegR); }

	CmpRegOffsetPtrReg( strRegL:Register, iOffsetL:OffsetPtr, strRegR:Register ):void {
        this.m_hX86Writer.putCmpRegOffsetPtrReg( strRegL, CodeWriter._ConvertOffsetPtr(iOffsetL), strRegR );
    }

	CmpImmPtrImm( ptrAddress:Pointer, immValue:number ):void { this.m_hX86Writer.putCmpImmPtrImmU32(ptrAddress.Handle, immValue); }

	CmpXChgRegPtrRegLock( strRegDst:Register, strRegSrc:Register ):void { this.m_hX86Writer.putLockCmpxchgRegPtrReg(strRegDst, strRegSrc); }

	TestRegImm( strReg:Register, immValue:number ):void   { this.m_hX86Writer.putTestRegU32(strReg, immValue); }
	TestRegReg( strRegL:Register, strRegR:Register ):void { this.m_hX86Writer.putTestRegReg(strRegL, strRegR); }
};

