////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM/CodeWriter.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Writer for ARM Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Integer64 } from "../Integer64";
import { UInteger64 } from "../UInteger64";
import { Pointer } from "../Pointer";

import { Register } from "./CPUContext";

import { OperandShifter } from "./CPUInstruction";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    ConditionCode,

    OffsetPtr,
    CallArgument,

    CodeWriterARM,
    CodeWriterThumb
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM Condition Codes
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
    AL = "al"
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM CodeWriter Helpers
type OffsetPtr =  number | Integer64 | UInteger64;
type CallArgument =  number | Integer64 | UInteger64 | Pointer | Register;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM CodeWriterARM
class CodeWriterARM
{
	// Members
    private m_hArmWriter:ArmWriter;
    
    // Helpers
    private static _ConvertOffsetPtr( iOffset:OffsetPtr ):number | Int64 | UInt64 {
        if ( iOffset instanceof Integer64 || iOffset instanceof UInteger64 )
            return iOffset.Handle;
        return iOffset;
    }
    private static _ConvertArguments( arrArguments:CallArgument[] ):ArmCallArgument[] {
        let arrArgs:ArmCallArgument[] = [];
        arrArguments.forEach( function(hArg:CallArgument):void {
            if ( hArg instanceof Integer64 || hArg instanceof UInteger64 || hArg instanceof Pointer )
                arrArgs.push( hArg.Handle );
            else
                arrArgs.push( hArg );
        });
        return arrArgs;
    }

    // Getter
	get Handle():ArmWriter { return this.m_hArmWriter; }

	// Constructor
	constructor( hArmWriter:ArmWriter ) {
		this.m_hArmWriter = hArmWriter;
	}
	static Create( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):CodeWriterARM {
		let hOptions:ArmWriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		return new CodeWriterARM( new ArmWriter(ptrCodeAddress.Handle, hOptions) );
    }
    Reset( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):void {
		let hOptions:ArmWriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		this.m_hArmWriter.reset( ptrCodeAddress.Handle, hOptions );
    }

    // Properties
	GetBasePointer():Pointer    { return new Pointer( this.m_hArmWriter.base ); }
	GetCodePointer():Pointer    { return new Pointer( this.m_hArmWriter.code ); }
	GetProgramCounter():Pointer { return new Pointer( this.m_hArmWriter.pc ); }
	GetOffset():number          { return this.m_hArmWriter.offset; }
    
    // Methods
	Cleanup():void { this.m_hArmWriter.dispose(); }
    Flush():void   { this.m_hArmWriter.flush(); }
    
    Skip( iBytes:number ):void { this.m_hArmWriter.skip(iBytes); }

    // Labels
    PutLabel( strLabel:string ):void { this.m_hArmWriter.putLabel(strLabel); }
    
    // Raw Code
	PutInstr( immValue:number ):void                          { this.m_hArmWriter.putInstruction(immValue); }
    PutBytes( arrBytes:string | number[] | ArrayBuffer ):void { this.m_hArmWriter.putBytes(arrBytes); }
    
    // NOPs
    NOP():void { this.m_hArmWriter.putNop(); }
    
    // Breakpoints
    BreakPoint():void             { this.m_hArmWriter.putBreakpoint(); }
    Break( immValue:number ):void { this.m_hArmWriter.putBrkImm(immValue); }
    
    // Flags
    LdrCPSR( strReg:Register ):void { this.m_hArmWriter.putMovCpsrReg(strReg); }
    StrCPSR( strReg:Register ):void { this.m_hArmWriter.putMovRegCpsr(strReg); }

    // Branching
    PutBranchAddress( ptrAddress:Pointer ):void { this.m_hArmWriter.putBranchAddress(ptrAddress.Handle); }

    CanBranchDirectly( ptrFrom:Pointer, ptrTo:Pointer ):boolean { return this.m_hArmWriter.canBranchDirectlyBetween(ptrFrom.Handle, ptrTo.Handle); }

    BImm( ptrAddress:Pointer ):void { this.m_hArmWriter.putBImm(ptrAddress.Handle); }
    BLabel( strLabel:string ):void  { this.m_hArmWriter.putBLabel(strLabel); }

    BccImm( strCC:ConditionCode, ptrAddress:Pointer ):void { this.m_hArmWriter.putBCondImm(strCC, ptrAddress.Handle); }
    BccLabel( strCC:ConditionCode, strLabel:string ):void  { this.m_hArmWriter.putBCondLabel(strCC, strLabel); }

    BLImm( ptrAddress:Pointer ):void { this.m_hArmWriter.putBlImm(ptrAddress.Handle); }
    BLLabel( strLabel:string ):void  { this.m_hArmWriter.putBlLabel(strLabel); }

    BXReg( strReg:Register ):void { this.m_hArmWriter.putBxReg(strReg); }

    BLXImm( ptrAddress:Pointer ):void { this.m_hArmWriter.putBlxImm(ptrAddress.Handle); }
    BLXReg( strReg:Register ):void    { this.m_hArmWriter.putBlxReg(strReg); }

    // Call / Ret
    FCall( ptrFunction:Pointer, arrArguments:CallArgument[] ):void {
        let arrArgs:ArmCallArgument[] = CodeWriterARM._ConvertArguments( arrArguments );
        this.m_hArmWriter.putCallAddressWithArguments( ptrFunction.Handle, arrArgs );
    }

    Ret():void { this.m_hArmWriter.putRet(); }

    // Load / Store
    LDRRegImm( strReg:Register, immValue:number ):void    { this.m_hArmWriter.putLdrRegU32(strReg, immValue); }
    LDRRegPtr( strReg:Register, ptrAddress:Pointer ):void { this.m_hArmWriter.putLdrRegAddress(strReg, ptrAddress.Handle); }
    LDRRegRegOffset( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hArmWriter.putLdrRegRegOffset( strRegDst, strRegSrc, CodeWriterARM._ConvertOffsetPtr(iOffsetSrc) );
    }

    LDRccRegRegOffset( strCC:ConditionCode, strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hArmWriter.putLdrCondRegRegOffset( strCC, strRegDst, strRegSrc, CodeWriterARM._ConvertOffsetPtr(iOffsetSrc) );
    }

    LDMIARegMask( strReg:Register, immValue:number ):void { this.m_hArmWriter.putLdmiaRegMask(strReg, immValue); }

    STRRegOffsetReg( strRegDst:Register, iOffsetDst:OffsetPtr, strRegSrc:Register ):void {
        this.m_hArmWriter.putStrRegRegOffset( strRegSrc, strRegDst, CodeWriterARM._ConvertOffsetPtr(iOffsetDst) );
    }

    STRccRegOffsetReg( strCC:ConditionCode, strRegDst:Register, iOffsetDst:OffsetPtr, strRegSrc:Register ):void {
        this.m_hArmWriter.putStrCondRegRegOffset( strCC, strRegSrc, strRegDst, CodeWriterARM._ConvertOffsetPtr(iOffsetDst) );
    }

    // Move
    MovRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hArmWriter.putMovRegReg(strRegDst, strRegSrc); }
    MovRegRegShift( strRegDst:Register, strRegSrc:Register, strShift:OperandShifter, immShiftValue:number ):void {
        this.m_hArmWriter.putMovRegRegShift( strRegDst, strRegSrc, strShift, immShiftValue );
    }

    // Arithmetics
    AddRegImm16( strReg:Register, immValue:number ):void                        { this.m_hArmWriter.putAddRegU16(strReg, immValue); }
    AddRegImm32( strReg:Register, immValue:number ):void                        { this.m_hArmWriter.putAddRegU32(strReg, immValue); }
    AddRegRegImm( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hArmWriter.putAddRegRegImm(strRegDst, strRegL, immValueR); }
    AddRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hArmWriter.putAddRegRegReg(strRegDst, strRegL, strRegR); }
    AddRegRegRegShift( strRegDst:Register, strRegL:Register, strRegR:Register, strShift:OperandShifter, immShiftValue:number ):void {
        this.m_hArmWriter.putAddRegRegRegShift( strRegDst, strRegL, strRegR, strShift, immShiftValue );
    }

    SubRegImm16( strReg:Register, immValue:number ):void                        { this.m_hArmWriter.putSubRegU16(strReg, immValue); }
    SubRegImm32( strReg:Register, immValue:number ):void                        { this.m_hArmWriter.putSubRegU32(strReg, immValue); }
    SubRegRegImm( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hArmWriter.putSubRegRegImm(strRegDst, strRegL, immValueR); }
    SubRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hArmWriter.putSubRegRegReg(strRegDst, strRegL, strRegR); }

    AndSRegRegImm( strRegDst:Register, strRegSrc:Register, immValue:number ):void { this.m_hArmWriter.putAndsRegRegImm(strRegDst, strRegSrc, immValue); }

    // Compare
    CmpRegImm( strReg:Register, immValue:number ):void { this.m_hArmWriter.putCmpRegImm(strReg, immValue); }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM CodeWriterThumb
class CodeWriterThumb
{
	// Members
    private m_hThumbWriter:ThumbWriter;
    
    // Helpers
    private static _ConvertOffsetPtr( iOffset:OffsetPtr ):number | Int64 | UInt64 {
        if ( iOffset instanceof Integer64 || iOffset instanceof UInteger64 )
            return iOffset.Handle;
        return iOffset;
    }
    private static _ConvertArguments( arrArguments:CallArgument[] ):ArmCallArgument[] {
        let arrArgs:ArmCallArgument[] = [];
        arrArguments.forEach( function(hArg:CallArgument):void {
            if ( hArg instanceof Integer64 || hArg instanceof UInteger64 || hArg instanceof Pointer )
                arrArgs.push( hArg.Handle );
            else
                arrArgs.push( hArg );
        });
        return arrArgs;
    }

    // Getter
	get Handle():ThumbWriter { return this.m_hThumbWriter; }

	// Constructor
	constructor( hThumbWriter:ThumbWriter ) {
		this.m_hThumbWriter = hThumbWriter;
	}
	static Create( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):CodeWriterThumb {
		let hOptions:ThumbWriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
        return new CodeWriterThumb( new ThumbWriter(ptrCodeAddress.Handle, hOptions) );
    }
    Reset( ptrCodeAddress:Pointer, ptrProgramCounter:Pointer | undefined ):void {
		let hOptions:ThumbWriterOptions = {
			pc: ( ptrProgramCounter != undefined ) ? ptrProgramCounter.Handle : undefined
		};
		this.m_hThumbWriter.reset( ptrCodeAddress.Handle, hOptions );
    }

    // Properties
	GetBasePointer():Pointer    { return new Pointer( this.m_hThumbWriter.base ); }
	GetCodePointer():Pointer    { return new Pointer( this.m_hThumbWriter.code ); }
	GetProgramCounter():Pointer { return new Pointer( this.m_hThumbWriter.pc ); }
	GetOffset():number          { return this.m_hThumbWriter.offset; }
    
    // Methods
	Cleanup():void { this.m_hThumbWriter.dispose(); }
    Flush():void   { this.m_hThumbWriter.flush(); }
    
    Skip( iBytes:number ):void { this.m_hThumbWriter.skip(iBytes); }

    // Labels
    PutLabel( strLabel:string ):void       { this.m_hThumbWriter.putLabel(strLabel); }
    CommitLabel( strLabel:string ):boolean { return this.m_hThumbWriter.commitLabel(strLabel); }

    // Raw Code
	PutInstr( immValue:number ):void                          { this.m_hThumbWriter.putInstruction(immValue); }
	PutInstrWide( immUpper:number, immLower:number ):void     { this.m_hThumbWriter.putInstructionWide(immUpper, immLower); }
    PutBytes( arrBytes:string | number[] | ArrayBuffer ):void { this.m_hThumbWriter.putBytes(arrBytes); }

    // NOPs
    NOP():void { this.m_hThumbWriter.putNop(); }
    
    // Breakpoints
    BreakPoint():void             { this.m_hThumbWriter.putBreakpoint(); }
    Break( immValue:number ):void { this.m_hThumbWriter.putBkptImm(immValue); }

    // Flags
    LdrCPSR( strReg:Register ):void { this.m_hThumbWriter.putMovCpsrReg(strReg); }
    StrCPSR( strReg:Register ):void { this.m_hThumbWriter.putMovRegCpsr(strReg); }

    // Stack
    PushRegs( arrRegs:Register[] ):void { this.m_hThumbWriter.putPushRegs(arrRegs); }
    PopRegs( arrRegs:Register[] ):void  { this.m_hThumbWriter.putPopRegs(arrRegs); }

    // Branching
    BImm( ptrAddress:Pointer ):void    { this.m_hThumbWriter.putBImm(ptrAddress.Handle); }
    BLabel( strLabel:string ):void     { this.m_hThumbWriter.putBLabel(strLabel); }
    BLabelWide( strLabel:string ):void { this.m_hThumbWriter.putBLabelWide(strLabel); }

    BeqLabel( strLabel:string ):void                          { this.m_hThumbWriter.putBeqLabel(strLabel); }
    BneLabel( strLabel:string ):void                          { this.m_hThumbWriter.putBneLabel(strLabel); }
    BccLabel( strCC:ConditionCode, strLabel:string ):void     { this.m_hThumbWriter.putBCondLabel(strCC, strLabel); }
    BccLabelWide( strCC:ConditionCode, strLabel:string ):void { this.m_hThumbWriter.putBCondLabelWide(strCC, strLabel); }

    CBzRegLabel( strReg:Register, strLabel:string ):void  { this.m_hThumbWriter.putCbzRegLabel(strReg, strLabel); }
    CBnzRegLabel( strReg:Register, strLabel:string ):void { this.m_hThumbWriter.putCbnzRegLabel(strReg, strLabel); }

    BLImm( ptrAddress:Pointer ):void { this.m_hThumbWriter.putBlImm(ptrAddress.Handle); }
    BLLabel( strLabel:string ):void  { this.m_hThumbWriter.putBlLabel(strLabel); }

    BXReg( strReg:Register ):void { this.m_hThumbWriter.putBxReg(strReg); }

    BLXImm( ptrAddress:Pointer ):void { this.m_hThumbWriter.putBlxImm(ptrAddress.Handle); }
    BLXReg( strReg:Register ):void    { this.m_hThumbWriter.putBlxReg(strReg); }

    // Call
    FCall( ptrFunction:Pointer, arrArguments:CallArgument[] ):void {
        let arrArgs:ArmCallArgument[] = CodeWriterThumb._ConvertArguments( arrArguments );
        this.m_hThumbWriter.putCallAddressWithArguments( ptrFunction.Handle, arrArgs );
    }
    FCallReg( strReg:Register, arrArguments:CallArgument[] ):void {
        let arrArgs:ArmCallArgument[] = CodeWriterThumb._ConvertArguments( arrArguments );
        this.m_hThumbWriter.putCallRegWithArguments( strReg, arrArgs );
    }

    // Load / Store
    LDRRegImm( strReg:Register, immValue:number ):void       { this.m_hThumbWriter.putLdrRegU32(strReg, immValue); }
    LDRRegPtr( strReg:Register, ptrAddress:Pointer ):void    { this.m_hThumbWriter.putLdrRegAddress(strReg, ptrAddress.Handle); }
    LDRRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hThumbWriter.putLdrRegReg(strRegDst, strRegSrc); }
    LDRRegRegOffset( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hThumbWriter.putLdrRegRegOffset( strRegDst, strRegSrc, CodeWriterThumb._ConvertOffsetPtr(iOffsetSrc) );
    }

    LDRBRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hThumbWriter.putLdrbRegReg(strRegDst, strRegSrc); }

    VLDRRegRegOffset( strRegDst:Register, strRegSrc:Register, iOffsetSrc:OffsetPtr ):void {
        this.m_hThumbWriter.putVldrRegRegOffset( strRegDst, strRegSrc, CodeWriterThumb._ConvertOffsetPtr(iOffsetSrc) );
    }

    LDMIARegMask( strReg:Register, immValue:number ):void { this.m_hThumbWriter.putLdmiaRegMask(strReg, immValue); }

    STRRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hThumbWriter.putStrRegReg(strRegSrc, strRegDst); }
    STRRegOffsetReg( strRegDst:Register, iOffsetDst:OffsetPtr, strRegSrc:Register ):void {
        this.m_hThumbWriter.putStrRegRegOffset( strRegSrc, strRegDst, CodeWriterThumb._ConvertOffsetPtr(iOffsetDst) );
    }

    // Move
    MovRegImm8( strRegDst:Register, immValue:number ):void   { this.m_hThumbWriter.putMovRegU8(strRegDst, immValue); }
    MovRegReg( strRegDst:Register, strRegSrc:Register ):void { this.m_hThumbWriter.putMovRegReg(strRegDst, strRegSrc); }

    MrsReg( strReg:Register ):void { this.m_hThumbWriter.putMrsRegReg(strReg, "apsr-nzcvq"); }
    MsrReg( strReg:Register ):void { this.m_hThumbWriter.putMsrRegReg("apsr-nzcvq", strReg); }

    // Arithmetics
    AddRegImm( strReg:Register, immValue:number ):void                          { this.m_hThumbWriter.putAddRegImm(strReg, immValue); }
    AddRegReg( strRegDst:Register, strRegSrc:Register ):void                    { this.m_hThumbWriter.putAddRegReg(strRegDst, strRegSrc); }
    AddRegRegImm( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hThumbWriter.putAddRegRegImm(strRegDst, strRegL, immValueR); }
    AddRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hThumbWriter.putAddRegRegReg(strRegDst, strRegL, strRegR); }
    
    SubRegImm( strReg:Register, immValue:number ):void                          { this.m_hThumbWriter.putSubRegImm(strReg, immValue); }
    SubRegReg( strRegDst:Register, strRegSrc:Register ):void                    { this.m_hThumbWriter.putSubRegReg(strRegDst, strRegSrc); }
    SubRegRegImm( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hThumbWriter.putSubRegRegImm(strRegDst, strRegL, immValueR); }
    SubRegRegReg( strRegDst:Register, strRegL:Register, strRegR:Register ):void { this.m_hThumbWriter.putSubRegRegReg(strRegDst, strRegL, strRegR); }

    AndRegRegImm( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hThumbWriter.putAndRegRegImm(strRegDst, strRegL, immValueR); }

    LSls( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hThumbWriter.putLslsRegRegImm(strRegDst, strRegL, immValueR); }
    LSrs( strRegDst:Register, strRegL:Register, immValueR:number ):void { this.m_hThumbWriter.putLsrsRegRegImm(strRegDst, strRegL, immValueR); }

    // Compare
    CmpRegImm( strReg:Register, immValue:number ):void { this.m_hThumbWriter.putCmpRegImm(strReg, immValue); }
}

