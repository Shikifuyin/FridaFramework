////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/System/Memory.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Memory Management
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { UInteger64 } from "../Native/UInteger64";
import { Pointer, StringEncoding } from "../Native/Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    AccessFlag,
    _ConvertFrom_AccessFlags,
    _ConvertTo_AccessFlags,

    Range,
    _ConvertTo_Range,

    ScanResult,
    ScanCallback,

    MonitorRange,
    MonitorInfos,
    MonitorCallback,

    PatchCodeCallBack,

    GetPointerSize,
    GetPageSize,

    HeapAlloc,
    PageAlloc,
    StringAlloc,
    ForceGC,

    Copy,
    Duplicate,
    SetAccessFlags,

    GetRange,
    EnumRanges,
    EnumMallocRanges,

    Scan,
    
    StartMonitor,
    StopMonitor,

    PatchCode
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Interfaces : Access Flags
const enum AccessFlag {
	Read    = 1,
	Write   = 2,
	Execute = 4
};

function _ConvertFrom_AccessFlags( iAccessFlags:number ):string {
    return (
        ( (iAccessFlags & AccessFlag.Read) ? "r" : "-" ) +
        ( (iAccessFlags & AccessFlag.Write) ? "w" : "-" ) +
        ( (iAccessFlags & AccessFlag.Execute) ? "x" : "-" )
    );
}
function _ConvertTo_AccessFlags( strProtection:string ):number {
    return (
        ( (strProtection[0] == "r") ? AccessFlag.Read : 0 ) |
        ( (strProtection[1] == "w") ? AccessFlag.Write : 0 ) |
        ( (strProtection[2] == "x") ? AccessFlag.Execute : 0 )
    );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Interfaces : Ranges
interface Range {
    BaseAddress:Pointer;
    Size:number;
    AccessFlags:number; // Memory.AccessFlag
    FileMapping?:{
        Path:string;
        Offset:number;
        Size:number;
    }
}

function _ConvertTo_Range( hRangeDetails:RangeDetails ):Range {
    let hConverted:Partial<Range> = {};
    hConverted.BaseAddress = new Pointer( hRangeDetails.base );
    hConverted.Size = hRangeDetails.size;
    hConverted.AccessFlags = _ConvertTo_AccessFlags( hRangeDetails.protection );

    if ( hRangeDetails.file != undefined ) {
        hConverted.FileMapping = {
            Path: hRangeDetails.file.path,
            Offset: hRangeDetails.file.offset,
            Size: hRangeDetails.file.size
        };
    }

    return ( hConverted as Range );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Interfaces : Scanner
interface ScanResult {
    Address:Pointer;
    Size:number;
}
interface ScanCallback {
    OnMatch( hResult:ScanResult ):boolean;
    OnComplete():void;
    OnError?( strError:string ):void;
}

function _ConvertTo_ScanResult( hMemoryScanMatch:MemoryScanMatch ):ScanResult {
    let hConverted:Partial<ScanResult> = {};
    hConverted.Address = new Pointer( hMemoryScanMatch.address );
    hConverted.Size = hMemoryScanMatch.size;

    return ( hConverted as ScanResult );
}
function _ConvertFrom_ScanCallback( hScanCallback:ScanCallback ):MemoryScanCallbacks {
    let hConverted:Partial<MemoryScanCallbacks> = {};

    hConverted.onMatch = function( ptrAddress:NativePointer, iSize:number ):EnumerateAction | void {
        let bContinue:boolean = hScanCallback.OnMatch({
            Address: new Pointer(ptrAddress),
            Size: iSize
        });
        if ( !bContinue )
            return "stop";
    };

    hConverted.onComplete = hScanCallback.OnComplete;
    hConverted.onError = hScanCallback.OnError;

    return ( hConverted as MemoryScanCallbacks );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Interfaces : Monitor
interface MonitorRange {
    BaseAddress:Pointer;
    Size:number;
}
interface MonitorInfos {
    InstructionAddress:Pointer; // Instruction triggering access
    AccessedAddress:Pointer;    // Addressed being accessed
    Operation:AccessFlag;       // Operation at AccessedAddress

    RangeIndex:number; // In the provided array
    PageIndex:number;  // Inside matched range

    InitialPagesCount:number;  // Monitored pages on start
    AccessedPagesCount:number; // No longer monitored
}
interface MonitorCallback {
    ( hInfos:MonitorInfos ):void;
}

function _ConvertFrom_MonitorRange( hMonitorRange:MonitorRange ):MemoryAccessRange {
    let hConverted:Partial<MemoryAccessRange> = {};
    hConverted.base = hMonitorRange.BaseAddress.Handle;
    hConverted.size = hMonitorRange.Size;

    return ( hConverted as MemoryAccessRange );
}
function _ConvertTo_MonitorInfos( hMemoryAccessDetails:MemoryAccessDetails ):MonitorInfos {
    let hConverted:Partial<MonitorInfos> = {};
    hConverted.InstructionAddress = new Pointer( hMemoryAccessDetails.from );
    hConverted.AccessedAddress = new Pointer( hMemoryAccessDetails.address );
    switch( hMemoryAccessDetails.operation ) {
        case "read":    hConverted.Operation = AccessFlag.Read; break;
        case "write":   hConverted.Operation = AccessFlag.Write; break;
        case "execute": hConverted.Operation = AccessFlag.Execute; break;
    }
    hConverted.RangeIndex = hMemoryAccessDetails.rangeIndex;
    hConverted.PageIndex = hMemoryAccessDetails.pageIndex;
    hConverted.InitialPagesCount = hMemoryAccessDetails.pagesTotal;
    hConverted.AccessedPagesCount = hMemoryAccessDetails.pagesCompleted;

    return ( hConverted as MonitorInfos );
}
function _ConvertFrom_MonitorCallback( hMonitorCallback:MonitorCallback ):MemoryAccessCallbacks {
    let hConverted:Partial<MemoryAccessCallbacks> = {};

    hConverted.onAccess = function( hDetails:MemoryAccessDetails ):void {
        hMonitorCallback( _ConvertTo_MonitorInfos(hDetails) );
    };

    return ( hConverted as MemoryAccessCallbacks );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Interfaces : Code Patcher
interface PatchCodeCallBack {
    // Create a CodeWriter at the provided address to apply your patch
    ( ptrCode:Pointer ):void;
}

function _ConvertFrom_PatchCodeCallBack( hPatchCodeCallBack:PatchCodeCallBack ):MemoryPatchApplyCallback {
    return function( ptrAddress:NativePointer ):void {
        hPatchCodeCallBack( new Pointer(ptrAddress) );
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Properties
function GetPointerSize():number {
    return Process.pointerSize;
}
function GetPageSize():number {
    return Process.pageSize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Allocator
function HeapAlloc( iSize:number | UInteger64 ):Pointer {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    return new Pointer( Memory.alloc(iConvertedSize) );
}
function PageAlloc( iPageCount:number ):Pointer {
    return new Pointer( Memory.alloc(iPageCount * Process.pageSize) );
}
function StringAlloc( strValue:string, iStringType:StringEncoding ):Pointer {
    switch( iStringType ) {
        case StringEncoding.ASCII: return Pointer.NULL; // Should never happen !
        case StringEncoding.UTF8:  return new Pointer( Memory.allocUtf8String(strValue) );
        case StringEncoding.UTF16: return new Pointer( Memory.allocUtf16String(strValue) );
        case StringEncoding.ANSI:  return new Pointer( Memory.allocAnsiString(strValue) );
    }
}

function ForceGC():void {
    gc();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Operations
function Copy( ptrDest:Pointer, ptrSrc:Pointer, iSize:number | UInteger64 ):void {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    Memory.copy( ptrDest.Handle, ptrSrc.Handle, iConvertedSize );
}
function Duplicate( ptrAddress:Pointer, iSize:number | UInteger64 ):void {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    Memory.dup( ptrAddress.Handle, iConvertedSize );
}

function SetAccessFlags( ptrAddress:Pointer, iSize:number | UInteger64, iAccessFlags:number ):boolean {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    let strProtection:string = _ConvertFrom_AccessFlags( iAccessFlags );
    return Memory.protect( ptrAddress.Handle, iConvertedSize, strProtection );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Ranges
function GetRange( ptrTargetAddress:Pointer, bThrowException:boolean = false ):Range | null {
    let hDesc:RangeDetails | null;
    if ( bThrowException )
        hDesc = Process.getRangeByAddress( ptrTargetAddress.Handle );
    else
        hDesc = Process.findRangeByAddress( ptrTargetAddress.Handle );

    if ( hDesc == null )
        return null;
    
    return _ConvertTo_Range( hDesc );
}

function EnumRanges( iAccess:number, bCoalesce:boolean = false ):Range[] {
    let hFilter:EnumerateRangesSpecifier = {
        protection: _ConvertFrom_AccessFlags(iAccess),
        coalesce: bCoalesce
    };
    let arrDescs:RangeDetails[] = Process.enumerateRanges( hFilter );

    let arrRanges:Range[] = [];
    arrDescs.forEach( function(hDesc:RangeDetails):void {
        arrRanges.push( _ConvertTo_Range(hDesc) );
    });
    return arrRanges;
}
function EnumMallocRanges():Range[] {
    let arrDescs:RangeDetails[] = Process.enumerateMallocRanges();
    
    let arrRanges:Range[] = [];
    arrDescs.forEach( function(hDesc:RangeDetails):void {
        arrRanges.push( _ConvertTo_Range(hDesc) );
    });
    return arrRanges;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Scanner
function Scan( ptrAddress:Pointer, iSize:number | UInteger64, strPattern:string, strMask:string | undefined = undefined,
               hCallbacks:ScanCallback | undefined = undefined ):ScanResult[] | void {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    if ( strMask != undefined )
        strPattern = strPattern + " : " + strMask;

    // Synchronous scan
    if ( hCallbacks == undefined ) {
        let arrDescs:MemoryScanMatch[] = Memory.scanSync( ptrAddress.Handle, iConvertedSize, strPattern );

        let arrResults:ScanResult[] = [];
        arrDescs.forEach( function( hMatch:MemoryScanMatch ):void {
            arrResults.push( _ConvertTo_ScanResult(hMatch) );
        });
        return arrResults;
    }

    // ASynchronous scan
    Memory.scan( ptrAddress.Handle, iConvertedSize, strPattern, _ConvertFrom_ScanCallback(hCallbacks) );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Monitor
function StartMonitor( arrRanges:MonitorRange[], hCallback:MonitorCallback ):void {
    let arrRangeDescs:MemoryAccessRange[] = [];
    arrRanges.forEach( function( hRange:MonitorRange ):void {
        arrRangeDescs.push( _ConvertFrom_MonitorRange(hRange) );
    });

    MemoryAccessMonitor.enable( arrRangeDescs, _ConvertFrom_MonitorCallback(hCallback) );
}
function StopMonitor():void {
    MemoryAccessMonitor.disable();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Code Patcher
function PatchCode( ptrAddress:Pointer, iSize:number | UInteger64, hCallback:PatchCodeCallBack ):void {
    let iConvertedSize:number | UInt64 = ( iSize instanceof UInteger64 ) ? iSize.Handle : iSize;
    Memory.patchCode( ptrAddress.Handle, iConvertedSize, _ConvertFrom_PatchCodeCallBack(hCallback) );
}

