////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Instrument/Stalker.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Instrumentation : Stalker
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import * as Native from "../Native/Native";

import { _ConvertTo_CPUContext } from "../Native/CPUContext"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    Event,
    EventExecuted,
    EventCall,
    EventRet,
    EventBlockCompiled,
    EventBlockExecuted,
    EventData,

    CalloutType,
    CalloutScript,
    CalloutNative,
    Callout,

    IteratorType,
    IteratorX86,
    IteratorARM,
    IteratorThumb,
    IteratorARM64,

    TransformCallbackType,
    TransformCallbackX86,
    TransformCallbackARM,
    TransformCallbackARM64,
    TransformCallbackNative,
    TransformCallback,

    CallProbeCallbackType,
    CallProbeCallbackScript,
    CallProbeCallbackNative,
    CallProbeCallback,

    GetTrustThreshold,
    SetTrustThreshold,
    GetQueueCapacity,
    SetQueueCapacity,
    GetQueueDrainInterval,
    SetQueueDrainInterval,

    Flush,
    ForceGC,

    Parse,

    CallSummary,
    FollowOptions,
    FollowExcludeRange,
    Follow,
    Unfollow,
    FollowExclude,

    CallProbeID,
    AddCallProbe,
    RemoveCallProbe
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : Events
enum Event {
    Executed = 'exec',
    Call = 'call',
    Ret = 'ret',
    BlockCompiled = 'compile',
    BlockExecuted = 'block'
};

interface EventExecuted {
    _type:Event;
    Location:Native.Pointer | string;
}
interface EventCall extends EventExecuted {
    Target:Native.Pointer | string;
    Depth:number;
}
interface EventRet extends EventExecuted {
    Target:Native.Pointer | string;
    Depth:number;
}
interface EventBlockCompiled extends EventExecuted {
    Target:Native.Pointer | string;
}
interface EventBlockExecuted extends EventExecuted {
    Target:Native.Pointer | string;
}

type EventData = EventExecuted | EventCall | EventRet | EventBlockCompiled | EventBlockExecuted;

function _ConvertTo_EventData( hEventData:StalkerEventFull ):EventData {
    let hBase:Partial<EventData> = {};
    hBase._type = Event[hEventData[0] as keyof typeof Event];
    hBase.Location = ( hEventData[1] instanceof NativePointer ) ? new Native.Pointer(hEventData[1]) : hEventData[1];

    switch( hBase._type ) {
        case Event.Executed: {
            let hConverted:EventExecuted = hBase as EventExecuted;
            return hConverted;
        }
        case Event.Call: {
            let hConverted:EventCall = hBase as EventCall;
            if ( hEventData[2] != undefined )
                hConverted.Target = ( hEventData[2] instanceof NativePointer ) ? new Native.Pointer(hEventData[2]) : hEventData[2];
            if ( hEventData[3] != undefined )
                hConverted.Depth = hEventData[3];
            return hConverted;
        }
        case Event.Ret: {
            let hConverted:EventRet = hBase as EventRet;
            if ( hEventData[2] != undefined )
                hConverted.Target = ( hEventData[2] instanceof NativePointer ) ? new Native.Pointer(hEventData[2]) : hEventData[2];
            if ( hEventData[3] != undefined )
                hConverted.Depth = hEventData[3];
            return hConverted;
        }
        case Event.BlockCompiled: {
            let hConverted:EventBlockCompiled = hBase as EventBlockCompiled;
            if ( hEventData[2] != undefined )
                hConverted.Target = ( hEventData[2] instanceof NativePointer ) ? new Native.Pointer(hEventData[2]) : hEventData[2];
            return hConverted;
        }
        case Event.BlockExecuted: {
            let hConverted:EventBlockExecuted = hBase as EventBlockExecuted;
            if ( hEventData[2] != undefined )
                hConverted.Target = ( hEventData[2] instanceof NativePointer ) ? new Native.Pointer(hEventData[2]) : hEventData[2];
            return hConverted;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : Callouts
const enum CalloutType {
    Script = "Script",
    Native = "Native"
};

interface CalloutScript {
    _type:CalloutType.Script;
    ( hContext:Native.CPUContext ):void;
}
interface CalloutNative {
    _type:CalloutType.Native;
    // Native C Code : void onAesEnc( GumCpuContext * cpu_context, gpointer user_data );
    Address:Native.Pointer;
}

type Callout = CalloutScript | CalloutNative;

function _ConvertFrom_Callout( hCallout:Callout ):StalkerCallout {
    switch( hCallout._type ) {
        case CalloutType.Script: {
            let hConverted:CalloutScript = hCallout as CalloutScript;
            return function( hContext:CpuContext ):void {
                hConverted( _ConvertTo_CPUContext(hContext) );
            };
        }
        case CalloutType.Native: {
            let hConverted:CalloutNative = hCallout as CalloutNative;
            return hConverted.Address.Handle;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : Code Iterators
const enum IteratorType {
    X86   = 'X86',
    ARM   = 'ARM',
    Thumb = 'Thumb',
    ARM64 = 'ARM64'
};

interface IteratorX86 extends Native.X86.CodeWriter {
    _type:IteratorType.X86;
    Next():Native.X86.CPUInstruction | null;
    Keep():void;
    PutCallout( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void;
}
interface IteratorARM extends Native.ARM.CodeWriterARM {
    _type:IteratorType.ARM;
    Next():Native.ARM.CPUInstruction | null;
    Keep():void;
    PutCallout( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void;
}
interface IteratorThumb extends Native.ARM.CodeWriterThumb {
    _type:IteratorType.Thumb;
    Next():Native.ARM.CPUInstruction | null;
    Keep():void;
    PutCallout( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void;
}
interface IteratorARM64 extends Native.ARM64.CodeWriter {
    _type:IteratorType.ARM64;
    Next():Native.ARM64.CPUInstruction | null;
    Keep():void;
    PutCallout( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void;
}

function _ConvertTo_IteratorX86( hIterator:StalkerX86Iterator ):IteratorX86 {
    let hConverted:Partial<IteratorX86> = new Native.X86.CodeWriter( hIterator );
    hConverted._type = IteratorType.X86;

    hConverted.Next = function():Native.X86.CPUInstruction | null {
        let hInstruction:X86Instruction | null = hIterator.next();
        if ( hInstruction == null )
            return null;
        return new Native.X86.CPUInstruction( hInstruction );
    };
    hConverted.Keep = hIterator.keep;
    hConverted.PutCallout = function( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void {
        let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
        hIterator.putCallout( _ConvertFrom_Callout(hCallout), ptrData );
    };
    
    return ( hConverted as IteratorX86 );
}
function _ConvertTo_IteratorARM( hIterator:StalkerArmIterator ):IteratorARM {
    let hConverted:Partial<IteratorARM> = new Native.ARM.CodeWriterARM( hIterator );
    hConverted._type = IteratorType.ARM;

    hConverted.Next = function():Native.ARM.CPUInstruction | null {
        let hInstruction:ArmInstruction | null = hIterator.next();
        if ( hInstruction == null )
            return null;
        return new Native.ARM.CPUInstruction( hInstruction );
    };
    hConverted.Keep = hIterator.keep;
    hConverted.PutCallout = function( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void {
        let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
        hIterator.putCallout( _ConvertFrom_Callout(hCallout), ptrData );
    };

    return ( hConverted as IteratorARM );
}
function _ConvertTo_IteratorThumb( hIterator:StalkerThumbIterator ):IteratorThumb {
    let hConverted:Partial<IteratorThumb> = new Native.ARM.CodeWriterThumb( hIterator );
    hConverted._type = IteratorType.Thumb;

    hConverted.Next = function():Native.ARM.CPUInstruction | null {
        let hInstruction:ArmInstruction | null = hIterator.next();
        if ( hInstruction == null )
            return null;
        return new Native.ARM.CPUInstruction( hInstruction );
    };
    hConverted.Keep = hIterator.keep;
    hConverted.PutCallout = function( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void {
        let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
        hIterator.putCallout( _ConvertFrom_Callout(hCallout), ptrData );
    };

    return ( hConverted as IteratorThumb );
}
function _ConvertTo_IteratorARM64( hIterator:StalkerArm64Iterator ):IteratorARM64 {
    let hConverted:Partial<IteratorARM64> = new Native.ARM64.CodeWriter( hIterator );
    hConverted._type = IteratorType.ARM64;

    hConverted.Next = function():Native.ARM64.CPUInstruction | null {
        let hInstruction:Arm64Instruction | null = hIterator.next();
        if ( hInstruction == null )
            return null;
        return new Native.ARM64.CPUInstruction( hInstruction );
    };
    hConverted.Keep = hIterator.keep;
    hConverted.PutCallout = function( hCallout:Callout, ptrUserData?:Native.Pointer | undefined ):void {
        let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
        hIterator.putCallout( _ConvertFrom_Callout(hCallout), ptrData );
    };

    return ( hConverted as IteratorARM64 );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : Transform Callbacks
const enum TransformCallbackType {
    X86    = 'X86',
    ARM    = 'ARM',
    ARM64  = 'ARM64',
    Native = 'Native'
};

interface TransformCallbackX86 {
    _type:TransformCallbackType.X86;
    (hIterator:IteratorX86):void;
}
interface TransformCallbackARM {
    _type:TransformCallbackType.ARM;
    (hIterator:IteratorARM | IteratorThumb):void;
}
interface TransformCallbackARM64 {
    _type:TransformCallbackType.ARM64;
    (hIterator:IteratorARM64):void;
}
interface TransformCallbackNative {
    _type:TransformCallbackType.Native;
    // Native C Code : void transform( GumStalkerIterator * iterator, GumStalkerOutput * output, gpointer user_data );
    Address:Native.Pointer;
}

type TransformCallback = TransformCallbackX86 | TransformCallbackARM | TransformCallbackARM64 | TransformCallbackNative;

function _ConvertFrom_TransformCallback( hTransformCallback:TransformCallback ):StalkerTransformCallback {
    switch( hTransformCallback._type ) {
        case TransformCallbackType.X86:
            return function( hIterator:StalkerX86Iterator ):void {
                hTransformCallback( _ConvertTo_IteratorX86(hIterator) );
            };
        case TransformCallbackType.ARM:
            return function( hIterator:StalkerArmIterator | StalkerThumbIterator ):void {
                if ( hIterator instanceof ArmWriter )
                    hTransformCallback( _ConvertTo_IteratorARM(hIterator) );
                else if ( hIterator instanceof ThumbWriter )
                    hTransformCallback( _ConvertTo_IteratorThumb(hIterator) );
            };
        case TransformCallbackType.ARM64:
            return function( hIterator:StalkerArm64Iterator ):void {
                hTransformCallback( _ConvertTo_IteratorARM64(hIterator) );
            };
        case TransformCallbackType.Native:
            return hTransformCallback.Address.Handle;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : CallProbe Callbacks
const enum CallProbeCallbackType {
    Script = 'Script',
    Native = 'Native'
};

interface CallProbeCallbackScript {
    _type:CallProbeCallbackType.Script;
    (arrParams:Native.Pointer[]):void;
}
interface CallProbeCallbackNative {
    _type:CallProbeCallbackType.Native;
    // Native C Code : void onCall (GumCallSite * site, gpointer user_data)
    Address:Native.Pointer;
}

type CallProbeCallback = CallProbeCallbackScript | CallProbeCallbackNative;

function _ConvertFrom_CallProbeCallback( hCallProbeCallback:CallProbeCallback ):StalkerCallProbeCallback {
    switch( hCallProbeCallback._type ) {
        case CallProbeCallbackType.Script:
            return function( arrParameters:NativePointer[] ):void {
                let arrParams:Native.Pointer[] = [];
                arrParameters.forEach( function(hParam:NativePointer) {
                    arrParams.push( new Native.Pointer(hParam) );
                });
                hCallProbeCallback( arrParams );
            };
        case CallProbeCallbackType.Native:
            return hCallProbeCallback.Address.Handle;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Interfaces : Follow Options
interface CallSummary {
    [Target: string]: number;
}
interface FollowOptions {
    Events?: {
        Executed?:boolean; // Not recommended !
        Call?:boolean;
        Ret?:boolean;
        BlockCompiled?:boolean;
        BlockExecuted?:boolean;
    }

    OnReceive?( arrEvents:ArrayBuffer ):void;
    OnCallSummary?( hSummary:CallSummary ):void;

    TransformUserData?:Native.Pointer;
    TransformCallback?:TransformCallback;
}
interface FollowExcludeRange {
    Base:Native.Pointer;
    Size:number;
}

function _ConvertFrom_FollowOptions( hFollowOptions:FollowOptions ):StalkerOptions {
    let hConverted:StalkerOptions = {};

    hConverted.events = undefined;
    if ( hFollowOptions.Events != undefined ) {
        hConverted.events = {};
        if ( hFollowOptions.Events.Executed != undefined )
            hConverted.events.exec = hFollowOptions.Events.Executed;
        if ( hFollowOptions.Events.Call != undefined )
            hConverted.events.call = hFollowOptions.Events.Call;
        if ( hFollowOptions.Events.Ret != undefined )
            hConverted.events.ret = hFollowOptions.Events.Ret;
        if ( hFollowOptions.Events.BlockCompiled != undefined )
            hConverted.events.compile = hFollowOptions.Events.BlockCompiled;
        if ( hFollowOptions.Events.BlockExecuted != undefined )
            hConverted.events.block = hFollowOptions.Events.BlockExecuted;
    }

    hConverted.onReceive = hFollowOptions.OnReceive;
    hConverted.onCallSummary = hFollowOptions.OnCallSummary;

    hConverted.data = undefined;
    if ( hFollowOptions.TransformUserData != undefined )
        hConverted.data = hFollowOptions.TransformUserData.Handle;

    hConverted.transform = undefined;
    if ( hFollowOptions.TransformCallback != undefined )
        hConverted.transform = _ConvertFrom_TransformCallback( hFollowOptions.TransformCallback );

    return hConverted;
}
function _ConvertFrom_FollowExcludeRange( hFollowExcludeRange:FollowExcludeRange ):MemoryRange {
    let hConverted:Partial<MemoryRange> = {};
    hConverted.base = hFollowExcludeRange.Base.Handle;
    hConverted.size = hFollowExcludeRange.Size;

    return ( hConverted as MemoryRange );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Properties
function GetTrustThreshold():number {
    return Stalker.trustThreshold;
}
function SetTrustThreshold( iValue:number ):void {
    Stalker.trustThreshold = iValue;
}

function GetQueueCapacity():number {
    return Stalker.queueCapacity;
}
function SetQueueCapacity( iValue:number ):void {
    Stalker.queueCapacity = iValue;
}

function GetQueueDrainInterval():number {
    return Stalker.queueDrainInterval;
}
function SetQueueDrainInterval( iValue:number ) {
    Stalker.queueDrainInterval = iValue;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Methods
function Flush():void {
    Stalker.flush();
}

function ForceGC():void {
    Stalker.garbageCollect();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Parsing
function Parse( arrEvents:ArrayBuffer, bStringifyPointers:boolean = false ):EventData[] {
    let hOptions:StalkerParseOptions = {};
    hOptions.annotate = true; // Force event type tag !
    hOptions.stringify = bStringifyPointers;

    let arrTmp:StalkerEventBare[] | StalkerEventFull[] = Stalker.parse( arrEvents, hOptions );

    let arrResults:EventData[] = [];
    arrTmp.forEach( function( hTmp:StalkerEventBare | StalkerEventFull ):void {
        arrResults.push( _ConvertTo_EventData(hTmp as StalkerEventFull) );
    });
    return arrResults;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Follow
function Follow( iThreadID:number | undefined, hOptions:FollowOptions | undefined ):void {
    let hOpt:StalkerOptions | undefined = undefined;
    if ( hOptions != undefined )
        hOpt = _ConvertFrom_FollowOptions( hOptions );
    Stalker.follow( iThreadID, hOpt );
}
function Unfollow( iThreadID:number | undefined ) {
    Stalker.unfollow( iThreadID );
}

function FollowExclude( hExcludedRange:FollowExcludeRange ):void {
    Stalker.exclude( _ConvertFrom_FollowExcludeRange(hExcludedRange) );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Stalker Call Probes
type CallProbeID = number;

function AddCallProbe( ptrAddress:Native.Pointer, hCallback:CallProbeCallback, ptrUserData:Native.Pointer | undefined ):CallProbeID {
    let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
    return Stalker.addCallProbe( ptrAddress.Handle, _ConvertFrom_CallProbeCallback(hCallback), ptrData );
}
function RemoveCallProbe( iProbeID:CallProbeID ):void {
    Stalker.removeCallProbe( iProbeID );
}
