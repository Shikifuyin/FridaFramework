////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Process/Kernel.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Kernel Access
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { assert } from "console";

import { Integer64 } from "../Native/Integer64";
import { UInteger64 } from "../Native/UInteger64";
import { StringEncoding } from "../Native/Pointer";

import { _ConvertFrom_AccessFlags, _ConvertTo_AccessFlags } from "../Memory/Memory";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    ModuleDescriptor,

    MemoryRange,
    ModuleMemoryRange,

    MemoryScanResult,
    MemoryScanCallback,

    IsAvailable,
    GetBaseAddress,
    GetPageSize,

    EnumModules,

    MemoryAlloc,

    ReadInt8,
    ReadInt16,
    ReadInt32,
    ReadShort,
    ReadInt,
    ReadInt64,
    ReadLong,
    ReadUInt8,
    ReadUInt16,
    ReadUInt32,
    ReadUShort,
    ReadUInt,
    ReadUInt64,
    ReadULong,
    ReadFloat,
    ReadDouble,
    ReadString,
    ReadByteArray,
    WriteInt8,
    WriteInt16,
    WriteInt32,
    WriteShort,
    WriteInt,
    WriteInt64,
    WriteLong,
    WriteUInt8,
    WriteUInt16,
    WriteUInt32,
    WriteUShort,
    WriteUInt,
    WriteUInt64,
    WriteULong,
    WriteFloat,
    WriteDouble,
    WriteString,
    WriteByteArray,
    SetMemoryAccessFlags,

    EnumMemoryRanges,
    EnumModuleMemoryRanges,

    Scan
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Interfaces : Modules
interface ModuleDescriptor {
    Name:string;
    BaseAddress:UInteger64;
    Size:number;
}

function _ConvertTo_ModuleDescriptor( hDetails:KernelModuleDetails ):ModuleDescriptor {
    let hConverted:Partial<ModuleDescriptor> = {};
    hConverted.Name = hDetails.name;
    hConverted.BaseAddress = new UInteger64( hDetails.base );
    hConverted.Size = hDetails.size;

    return ( hConverted as ModuleDescriptor );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Interfaces : Ranges
interface MemoryRange {
    BaseAddress:UInteger64;
    Size:number;
    AccessFlags:number;
}
interface ModuleMemoryRange {
    NameID:string;
    BaseAddress:UInteger64;
    Size:number;
    AccessFlags:number;
}

function _ConvertTo_MemoryRange( hDetails:KernelRangeDetails ):MemoryRange {
    let hConverted:Partial<MemoryRange> = {};
    hConverted.BaseAddress = new UInteger64( hDetails.base );
    hConverted.Size = hDetails.size;
    hConverted.AccessFlags = _ConvertTo_AccessFlags( hDetails.protection );

    return ( hConverted as MemoryRange );
}
function _ConvertTo_ModuleMemoryRange( hDetails:KernelModuleRangeDetails ):ModuleMemoryRange {
    let hConverted:Partial<ModuleMemoryRange> = {};
    hConverted.NameID = hDetails.name;
    hConverted.BaseAddress = new UInteger64( hDetails.base );
    hConverted.Size = hDetails.size;
    hConverted.AccessFlags = _ConvertTo_AccessFlags( hDetails.protection );

    return ( hConverted as ModuleMemoryRange );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Interfaces : Scanner
interface MemoryScanResult {
    Address:UInteger64;
    Size:number;
}
interface MemoryScanCallback {
    OnMatch( hResult:MemoryScanResult ):boolean;
    OnComplete():void;
    OnError?( strError:string ):void;
}

function _ConvertTo_MemoryScanResult( hKernelMemoryScanMatch:KernelMemoryScanMatch ):MemoryScanResult {
    let hConverted:Partial<MemoryScanResult> = {};
    hConverted.Address = new UInteger64( hKernelMemoryScanMatch.address );
    hConverted.Size = hKernelMemoryScanMatch.size;

    return ( hConverted as MemoryScanResult );
}
function _ConvertFrom_MemoryScanCallback( hMemoryScanCallback:MemoryScanCallback ):KernelMemoryScanCallbacks {
    let hConverted:Partial<KernelMemoryScanCallbacks> = {};

    hConverted.onMatch = function( ptrAddress:UInt64, iSize:number ):EnumerateAction | void {
        let bContinue:boolean = hMemoryScanCallback.OnMatch({
            Address: new UInteger64(ptrAddress),
            Size: iSize
        });
        if ( !bContinue )
            return "stop";
    };

    hConverted.onComplete = hMemoryScanCallback.OnComplete;
    hConverted.onError = hMemoryScanCallback.OnError;

    return ( hConverted as KernelMemoryScanCallbacks );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Properties
function IsAvailable():boolean {
    return Kernel.available;
}

function GetBaseAddress():UInteger64 {
    return new UInteger64( Kernel.base );
}
function GetPageSize():number {
    return Kernel.pageSize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Modules
function EnumModules():ModuleDescriptor[] {
    let arrDescs:KernelModuleDetails[] = Kernel.enumerateModules();

    let arrResults:ModuleDescriptor[] = [];
    arrDescs.forEach( function( hDesc:KernelModuleDetails ):void {
        arrResults.push( _ConvertTo_ModuleDescriptor(hDesc) );
    });
    return arrResults;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Memory Allocator
function MemoryAlloc( iSize:number | UInteger64 ):UInteger64 {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    return new UInteger64( Kernel.alloc(iConvertedSize) );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Memory Operations

// Read
function ReadInt8( iAddress:UInteger64 ):number { return Kernel.readS8(iAddress.Handle); }
function ReadInt16( iAddress:UInteger64 ):number { return Kernel.readS16(iAddress.Handle); }
function ReadInt32( iAddress:UInteger64 ):number { return Kernel.readS32(iAddress.Handle); }
function ReadShort( iAddress:UInteger64 ):number { return Kernel.readShort(iAddress.Handle); }
function ReadInt( iAddress:UInteger64 ):number { return Kernel.readInt(iAddress.Handle); }

function ReadInt64( iAddress:UInteger64 ):Integer64 { return new Integer64( Kernel.readS64(iAddress.Handle) ); }
function ReadLong( iAddress:UInteger64 ):Integer64 | number {
    let iValue:Int64 | number = Kernel.readLong( iAddress.Handle );
    return ( iValue instanceof Int64 ) ? new Integer64(iValue) : iValue;
}

function ReadUInt8( iAddress:UInteger64 ):number { return Kernel.readU8(iAddress.Handle); }
function ReadUInt16( iAddress:UInteger64 ):number { return Kernel.readU16(iAddress.Handle); }
function ReadUInt32( iAddress:UInteger64 ):number { return Kernel.readU32(iAddress.Handle); }
function ReadUShort( iAddress:UInteger64 ):number { return Kernel.readUShort(iAddress.Handle); }
function ReadUInt( iAddress:UInteger64 ):number { return Kernel.readUInt(iAddress.Handle); }

function ReadUInt64( iAddress:UInteger64 ):UInteger64 { return new UInteger64( Kernel.readU64(iAddress.Handle) ); }
function ReadULong( iAddress:UInteger64 ):UInteger64 | number {
    let iValue:UInt64 | number = Kernel.readULong( iAddress.Handle );
    return ( iValue instanceof UInt64 ) ? new UInteger64(iValue) : iValue;
}

function ReadFloat( iAddress:UInteger64 ):number  { return Kernel.readFloat(iAddress.Handle); }
function ReadDouble( iAddress:UInteger64 ):number { return Kernel.readDouble(iAddress.Handle); }

function ReadString( iAddress:UInteger64, iType:StringEncoding, iLength:number ):string | null {
    switch( iType ) {
        case StringEncoding.ASCII: return Kernel.readCString( iAddress.Handle, iLength );
        case StringEncoding.UTF8:  return Kernel.readUtf8String( iAddress.Handle, iLength );
        case StringEncoding.UTF16: return Kernel.readUtf16String( iAddress.Handle, iLength );
        case StringEncoding.ANSI:
        default: assert(false); return null; // Should never happen
    }
}

function ReadByteArray( iAddress:UInteger64, iSize:number ):ArrayBuffer | null { return Kernel.readByteArray(iAddress.Handle, iSize); }

// Write
function _TypeCastInt64( mValue:number | Integer64 ):number | Int64 {
    return ( mValue instanceof Integer64 ) ? mValue.Handle : mValue;
}
function _TypeCastUInt64( mValue:number | UInteger64 ):number | UInt64 {
    return ( mValue instanceof UInteger64 ) ? mValue.Handle : mValue;
}

function WriteInt8( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeS8( iAddress.Handle, _TypeCastInt64(iValue) );
}
function WriteInt16( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeS16( iAddress.Handle, _TypeCastInt64(iValue) );
}
function WriteInt32( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeS32( iAddress.Handle, _TypeCastInt64(iValue) );
}
function WriteShort( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeShort( iAddress.Handle, _TypeCastInt64(iValue) );
}
function WriteInt( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeInt( iAddress.Handle, _TypeCastInt64(iValue) );
}

function WriteInt64( iAddress:UInteger64, iValue:number | Integer64 ):void {
    Kernel.writeS64( iAddress.Handle, _TypeCastInt64(iValue) );
}
function WriteLong( iAddress:UInteger64, iValue:number | Integer64 ):void  {
    Kernel.writeLong( iAddress.Handle, _TypeCastInt64(iValue) );
}

function WriteUInt8( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeU8( iAddress.Handle, _TypeCastUInt64(iValue) );
}
function WriteUInt16( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeU16( iAddress.Handle, _TypeCastUInt64(iValue) );
}
function WriteUInt32( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeU32( iAddress.Handle, _TypeCastUInt64(iValue) );
}
function WriteUShort( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeUShort( iAddress.Handle, _TypeCastUInt64(iValue) );
}
function WriteUInt( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeUInt( iAddress.Handle, _TypeCastUInt64(iValue) );
}

function WriteUInt64( iAddress:UInteger64, iValue:number | UInteger64 ):void {
    Kernel.writeU64( iAddress.Handle, _TypeCastUInt64(iValue) );
}
function WriteULong( iAddress:UInteger64, iValue:number | UInteger64 ):void  {
    Kernel.writeULong( iAddress.Handle, _TypeCastUInt64(iValue) );
}

function WriteFloat( iAddress:UInteger64, fValue:number ):void  { Kernel.writeFloat(iAddress.Handle, fValue); }
function WriteDouble( iAddress:UInteger64, fValue:number ):void { Kernel.writeDouble(iAddress.Handle, fValue); }

function WriteString( iAddress:UInteger64, iType:StringEncoding, strValue:string ):void {
    switch( iType ) {
        case StringEncoding.UTF8:  Kernel.writeUtf8String( iAddress.Handle, strValue ); break;
        case StringEncoding.UTF16: Kernel.writeUtf16String( iAddress.Handle, strValue ); break;
        case StringEncoding.ASCII:
        case StringEncoding.ANSI:
        default: assert(false); break; // Should never happen
    }
}

function WriteByteArray( iAddress:UInteger64, arrBytes:number[] | ArrayBuffer ):void {
    Kernel.writeByteArray( iAddress.Handle, arrBytes );
}

function SetMemoryAccessFlags( ptrAddress:UInteger64, iSize:number | UInteger64, iAccessFlags:number ):boolean {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    let strProtection:string = _ConvertFrom_AccessFlags( iAccessFlags );
    return Kernel.protect( ptrAddress.Handle, iConvertedSize, strProtection );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Memory Ranges
function EnumMemoryRanges( iAccess:number, bCoalesce:boolean = false ):MemoryRange[] {
    let hFilter:EnumerateRangesSpecifier = {
        protection: _ConvertFrom_AccessFlags( iAccess ),
        coalesce: bCoalesce
    };
    let arrDescs:KernelRangeDetails[] = Kernel.enumerateRanges( hFilter );

    let arrRanges:MemoryRange[] = [];
    arrDescs.forEach( function( hDesc:KernelRangeDetails) :void {
        arrRanges.push( _ConvertTo_MemoryRange(hDesc) );
    });
    return arrRanges;
}
function EnumModuleMemoryRanges( strModuleName:string, iAccess:number ):ModuleMemoryRange[] {
    let strProtection:string = _ConvertFrom_AccessFlags( iAccess );
    let arrDescs:KernelModuleRangeDetails[] = Kernel.enumerateModuleRanges( strModuleName, strProtection );

    let arrRanges:ModuleMemoryRange[] = [];
    arrDescs.forEach( function( hDesc:KernelModuleRangeDetails ):void {
        arrRanges.push( _ConvertTo_ModuleMemoryRange(hDesc) );
    });
    return arrRanges;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel Memory Scanner
function Scan( ptrAddress:UInteger64, iSize:number | UInteger64, strPattern:string,
               strMask:string | undefined = undefined,
               hCallbacks:MemoryScanCallback | undefined = undefined ):MemoryScanResult[] | void {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    if ( strMask != undefined )
        strPattern = strPattern + " : " + strMask;

    // Synchronous scan
    if ( hCallbacks == undefined ) {
        let arrDescs:KernelMemoryScanMatch[] = Kernel.scanSync( ptrAddress.Handle, iConvertedSize, strPattern );

        let arrResults:MemoryScanResult[] = [];
        arrDescs.forEach( function( hMatch:KernelMemoryScanMatch ):void {
            arrResults.push( _ConvertTo_MemoryScanResult(hMatch) );
        });
        return arrResults;
    }

    // ASynchronous scan
    Kernel.scan( ptrAddress.Handle, iConvertedSize, strPattern, _ConvertFrom_MemoryScanCallback(hCallbacks) );
}

