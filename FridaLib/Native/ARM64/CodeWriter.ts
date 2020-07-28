////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM64/CodeWriter.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Writer for ARM64 Architecture
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
    ConditionCode,
    IndexMode,

    OffsetPtr,
    CallArgument,

    CodeWriter
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 Condition Codes
const enum ConditionCode {
    EQ = "eq",
    NE = "ne",
    HS = "hs",
    LO = "lo",
    MI = "mi",
    PL = "pl",
    VS = "vs",
    VC = "vc",
    HI = "hi",
    LS = "ls",
    GE = "ge",
    LT = "lt",
    GT = "gt",
    LE = "le",
    AL = "al",
    NV = "nv"
};

const enum IndexMode {
    PreAdjust    = "pre-adjust",
    PostAdjust   = "post-adjust",
    SignedOffset = "signed-offset"
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 CodeWriter Helpers
type OffsetPtr =  number | Integer64 | UInteger64;
type CallArgument =  number | Integer64 | UInteger64 | Pointer | Register;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 CodeWriter
class CodeWriter
{
	// Members
    private m_hArm64Writer:Arm64Writer;
    
    // Helpers
    private static _ConvertOffsetPtr( iOffset:OffsetPtr ):number | Int64 | UInt64 {
        if ( iOffset instanceof Integer64 || iOffset instanceof UInteger64 )
            return iOffset.Handle;
        return iOffset;
    }
    private static _ConvertArguments( arrArguments:CallArgument[] ):Arm64CallArgument[] {
        let arrArgs:Arm64CallArgument[] = [];
        arrArguments.forEach( function(hArg:CallArgument):void {
            if ( hArg instanceof Integer64 || hArg instanceof UInteger64 || hArg instanceof Pointer )
                arrArgs.push( hArg.Handle );
            else
                arrArgs.push( hArg );
        });
        return arrArgs;
    }

    // Getter
	get Handle():Arm64Writer { return this.m_hArm64Writer; }

	// Constructor
	constructor( hArm64Writer:Arm64Writer ) {
		this.m_hArm64Writer = hArm64Writer;
	}
	static Create( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):CodeWriter {
		let hOptions:Arm64WriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		return new CodeWriter( new Arm64Writer(ptrCodeAddress.Handle, hOptions) );
    }
    Reset( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):void {
		let hOptions:Arm64WriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		this.m_hArm64Writer.reset( ptrCodeAddress.Handle, hOptions );
    }

    // Properties
	GetBasePointer():Pointer    { return new Pointer( this.m_hArm64Writer.base ); }
	GetCodePointer():Pointer    { return new Pointer( this.m_hArm64Writer.code ); }
	GetProgramCounter():Pointer { return new Pointer( this.m_hArm64Writer.pc ); }
	GetOffset():number          { return this.m_hArm64Writer.offset; }
    
    // Methods
	Cleanup():void { this.m_hArm64Writer.dispose(); }
    Flush():void   { this.m_hArm64Writer.flush(); }
    
    Skip( iBytes:number ):void { this.m_hArm64Writer.skip(iBytes); }

    // Labels
    PutLabel( strLabel:string ):void { this.m_hArm64Writer.putLabel(strLabel); }
    
    // Raw Code
	PutInstr( immValue:number ):void                          { this.m_hArm64Writer.putInstruction(immValue); }
    PutBytes( arrBytes:string | number[] | ArrayBuffer ):void { this.m_hArm64Writer.putBytes(arrBytes); }
    
    // NOPs
    NOP():void { this.m_hArm64Writer.putNop(); }
    
    // Breakpoints
    Break( immValue:number ):void { this.m_hArm64Writer.putBrkImm(immValue); }
    
    // Pointer authentication
    Sign( ptrAddress:Pointer ):void { this.m_hArm64Writer.sign(ptrAddress.Handle); }
    Unsign( strReg:Register ):void  { this.m_hArm64Writer.putXpaciReg(strReg); }

    // Stack
    PushRegReg( strRegA:Register, strRegB:Register ):void { this.m_hArm64Writer.putPushRegReg(strRegA, strRegB); }
    PushAllX():void { this.m_hArm64Writer.putPushAllXRegisters(); }
    PushAllQ():void { this.m_hArm64Writer.putPushAllQRegisters(); }

    PopRegReg( strRegA:Register, strRegB:Register ):void  { this.m_hArm64Writer.putPopRegReg(strRegA, strRegB); }
    PopAllX():void { this.m_hArm64Writer.putPopAllXRegisters(); }
    PopAllQ():void { this.m_hArm64Writer.putPopAllQRegisters(); }

    // Branching
    PutBranchAddress( ptrAddress:Pointer ):void { this.m_hArm64Writer.putBranchAddress(ptrAddress.Handle); }

    CanBranchDirectly( ptrFrom:Pointer, ptrTo:Pointer ):boolean { return this.m_hArm64Writer.canBranchDirectlyBetween(ptrFrom.Handle, ptrTo.Handle); }

    BImm( ptrAddress:Pointer ):void { this.m_hArm64Writer.putBImm(ptrAddress.Handle); }
    BLabel( strLabel:string ):void  { this.m_hArm64Writer.putBLabel(strLabel); }

    BccLabel( strCC:ConditionCode, strLabel:string ):void  { this.m_hArm64Writer.putBCondLabel(strCC, strLabel); }

    CBzRegLabel( strReg:Register, strLabel:string ):void  { this.m_hArm64Writer.putCbzRegLabel(strReg, strLabel); }
    CBnzRegLabel( strReg:Register, strLabel:string ):void { this.m_hArm64Writer.putCbnzRegLabel(strReg, strLabel); }

    TBzRegImmLabel( strReg:Register, immValue:number, strLabel:string ):void  { this.m_hArm64Writer.putTbzRegImmLabel(strReg, immValue, strLabel); }
    TBnzRegImmLabel( strReg:Register, immValue:number, strLabel:string ):void { this.m_hArm64Writer.putTbnzRegImmLabel(strReg, immValue, strLabel); }

    BLImm( ptrAddress:Pointer ):void { this.m_hArm64Writer.putBlImm(ptrAddress.Handle); }
    BLLabel( strLabel:string ):void  { this.m_hArm64Writer.putBlLabel(strLabel); }

    BRReg( strReg:Register ):void       { this.m_hArm64Writer.putBrReg(strReg); }
    BRRegNoAuth( strReg:Register ):void { this.m_hArm64Writer.putBrRegNoAuth(strReg); }

    BLRReg( strReg:Register ):void       { this.m_hArm64Writer.putBlrReg(strReg); }
    BLRRegNoAuth( strReg:Register ):void { this.m_hArm64Writer.putBlrRegNoAuth(strReg); }

    // Call / Ret
    FCall( ptrFunction:Pointer, arrArguments:CallArgument[] ):void {
        let arrArgs:Arm64CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hArm64Writer.putCallAddressWithArguments( ptrFunction.Handle, arrArgs );
    }
    FCallReg( strReg:Register, arrArguments:CallArgument[] ):void {
        let arrArgs:Arm64CallArgument[] = CodeWriter._ConvertArguments( arrArguments );
        this.m_hArm64Writer.putCallRegWithArguments( strReg, arrArgs );
    }

    Ret():void { this.m_hArm64Writer.putRet(); }

    // Load / Store
    LDRRegImm( strReg:Register, immValue:number | UInteger64 ):void {
        this.m_hArm64Writer.putLdrRegU64( strReg, CodeWriter._ConvertOffsetPtr(immValue) );
    }
    LDRRegPtr( strReg:Register, ptrAddress:Pointer ):void { this.m_hArm64Writer.putLdrRegAddress(strReg, ptrAddress.Handle); }
    LDRRegRegOffset( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hArm64Writer.putLdrRegRegOffset( strRegDst, strRegSrc, CodeWriter._ConvertOffsetPtr(iOffsetSrc) );
    }
    LDRSWRegRegOffset( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hArm64Writer.putLdrswRegRegOffset( strRegDst, strRegSrc, CodeWriter._ConvertOffsetPtr(iOffsetSrc) );
    }

    LDRRegRef( strReg:Register ):number                 { return this.m_hArm64Writer.putLdrRegRef(strReg); }
    LDRRegValue( iRef:number, ptrAddress:Pointer ):void { this.m_hArm64Writer.putLdrRegValue(iRef, ptrAddress.Handle); }

    ADRPRegPtr( strReg:Register, ptrAddress:Pointer ):void { this.m_hArm64Writer.putAdrpRegAddress(strReg, ptrAddress.Handle); }

    LDPRegRegRegOffset( strRegA:Register, strRegB:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr, iIndexMode:IndexMode ):void {
        this.m_hArm64Writer.putLdpRegRegRegOffset( strRegA, strRegB, strRegSrc, CodeWriter._ConvertOffsetPtr(iOffsetSrc), iIndexMode );
    }

    STRRegOffsetReg( strRegDst:Register, iOffsetDst:OffsetPtr, strRegSrc:Register ):void {
        this.m_hArm64Writer.putStrRegRegOffset( strRegSrc, strRegDst, CodeWriter._ConvertOffsetPtr(iOffsetDst) );
    }

    STPRegRegRegOffset( strRegA:Register, strRegB:Register, strRegDst:Register, iOffsetDst:OffsetPtr, iIndexMode:IndexMode ):void {
        this.m_hArm64Writer.putStpRegRegRegOffset( strRegA, strRegB, strRegDst, CodeWriter._ConvertOffsetPtr(iOffsetDst), iIndexMode );
    }

    // Move
    MovRegReg( strRegDst:Register, strRegSrc:Register ):void  { this.m_hArm64Writer.putMovRegReg(strRegDst, strRegSrc); }
    UXTWRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hArm64Writer.putUxtwRegReg(strRegDst, strRegSrc); }

    // Arithmetics
    AddRegRegImm( strRegDst:Register, strRegL:Register, immValueR:OffsetPtr ):void {
        this.m_hArm64Writer.putAddRegRegImm( strRegDst, strRegL, CodeWriter._ConvertOffsetPtr(immValueR) );
    }
    AddRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hArm64Writer.putAddRegRegReg(strRegDst, strRegL, strRegR); }

    SubRegRegImm( strRegDst:Register, strRegL:Register, immValueR:OffsetPtr ):void {
        this.m_hArm64Writer.putSubRegRegImm( strRegDst, strRegL, CodeWriter._ConvertOffsetPtr(immValueR) );
    }
    SubRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hArm64Writer.putSubRegRegReg(strRegDst, strRegL, strRegR); }

    AndRegRegImm( strRegDst:Register, strRegL:Register, immValueR:OffsetPtr ):void {
        this.m_hArm64Writer.putAndRegRegImm( strRegDst, strRegL, CodeWriter._ConvertOffsetPtr(immValueR) );
    }

    // Compare & Test
    CmpRegReg( strRegA:Register, strRegB:Register ):void { this.m_hArm64Writer.putCmpRegReg(strRegA, strRegB); }
    TestRegImm( strReg:Register, immValue:number | UInteger64 ):void {
        this.m_hArm64Writer.putTstRegImm( strReg, CodeWriter._ConvertOffsetPtr(immValue) );
    }
}
