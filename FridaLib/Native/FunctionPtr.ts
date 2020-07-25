////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/FunctionPtr.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Native Function Pointer type
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Integer64 } from "./Integer64";
import { UInteger64 } from "./UInteger64";
import { Pointer } from "./Pointer"

import { CPUContext, _ConvertTo_CPUContext } from "./CPUContext";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    CallingConvention,
    FunctionPtrOptions,

    InvokeContext,
    _ConvertTo_InvokeContext,

    NativeType,
    FunctionSignatureType,
    FunctionParamValue,
    FunctionReturnValue,
    FunctionSystemReturnValue,
    CallbackImplementation,

    FunctionPtr,
    SystemFunctionPtr,
    CallBackFunctionPtr
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FunctionPtr Interfaces : Options
const enum CallingConvention {
    Default = 'default',
    SysCall = 'sysv',

        // Win32
    StdCall  = 'stdcall',
    ThisCall = 'thiscall',
    FastCall = 'fastcall',
    CDecl    = 'mscdecl',

        // Win64
    Win64 = 'win64',

        // UNIX
    UNIX64 = 'unix64',

        // UNIX ARM
    VFP = 'vfp'
};

interface FunctionPtrOptions {
    CallingConvention?:CallingConvention;

    // ExclusiveLock = false => Cooperative mode, Release JS lock before calling the function, reacquire afterwards. (Default)
	// ExclusiveLock = true  => Exclusive mode, Hold the JS lock while calling the function, can cause deadlocks !
    ExclusiveLock?:boolean;

    // PropagateExceptions = false => Unwind stack & steal exceptions to pass them to JS, prevents process crash but
	//                                can leave the app in an undefined state. (Default)
	// PropagateExceptions = true  => Let the app deal with exceptions. Can still deal with them by overriding the handler
	//                                with FridaTB.Process.RegisterExceptionHandler.
    PropagateExceptions?:boolean;

    // TrapAll = false => Only Interceptor hooks are active. (Default)
	// TrapAll = true  => Both Interceptor and Stalker hooks are active.
    TrapAll?:boolean;
}

function _ConvertFrom_FunctionPtrOptions( hOptions:FunctionPtrOptions ):NativeFunctionOptions {
    let hConverted:NativeFunctionOptions = {};

    if ( hOptions.CallingConvention != undefined ) hConverted.abi = hOptions.CallingConvention;
    if ( hOptions.ExclusiveLock != undefined ) {
        hConverted.scheduling = hOptions.ExclusiveLock ? 'exclusive' : 'cooperative';
    }
    if ( hOptions.PropagateExceptions != undefined ) {
        hConverted.exceptions = hOptions.PropagateExceptions ? 'propagate' : 'steal';
    }
    if ( hOptions.TrapAll != undefined ) {
        hConverted.traps = hOptions.TrapAll ? 'all' : 'default';
    }

    return hConverted;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FunctionPtr Interfaces : Invocation Context
interface InvokeContext {
    ThreadID:number;
    CallDepth:number;

    ReturnAddress:Pointer;
    Context:CPUContext; // You can update registers by assigning these ...

    // Error Information
    Error?:number; // lastError on Windows / errno on UNIX

    // Allows to transmit custom data between events
    [UserData:string]:any;
}

function _ConvertTo_InvokeContext( hContext:InvocationContext ):InvokeContext {
    let hConverted:Partial<InvokeContext> = {};

    hConverted.ThreadID = hContext.threadId;
    hConverted.CallDepth = hContext.depth;
    hConverted.ReturnAddress = new Pointer( hContext.returnAddress );

    hConverted.Context = _ConvertTo_CPUContext( hContext.context );

    if ( hContext.lastError != undefined )
        hConverted.Error = hContext.lastError;
    else if ( hContext.errno != undefined )
        hConverted.Error = hContext.errno;

    const arrUserDataKeys:string[] = Object.keys( hContext );
    arrUserDataKeys.forEach( function(hDataKey:string) {
        hConverted[hDataKey] = hContext[hDataKey];
    });

    return ( hConverted as InvokeContext );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FunctionPtr Interfaces : Callback Declaration & Implementation
const enum NativeType {
    Void    = 'void',
    Pointer = 'pointer',

    Bool = 'bool',

    Char  = 'char',
    Short = 'short',
    Int   = 'int',
    Long  = 'long',

    UChar  = 'uchar',
    UShort = 'ushort',
    UInt   = 'uint',
    ULong  = 'ulong',

    Int8  = 'int8',
    Int16 = 'int16',
    Int32 = 'int32',
    Int64 = 'int64',

    UInt8  = 'uint8',
    UInt16 = 'uint16',
    UInt32 = 'uint32',
    UInt64 = 'uint64',

    Float  = 'float',
    Double = 'double',

    Variadic = '...'
};

type FunctionSignatureType = NativeType | any[];

type FunctionParamValue = number | boolean | Integer64 | UInteger64 | Pointer | any[];
type FunctionReturnValue = number | boolean | Integer64 | UInteger64 | Pointer | any[];
interface FunctionSystemReturnValue {
    Value:FunctionReturnValue;
    Error:number; // lastError / errno
}

interface CallbackImplementation {
    ( this:InvokeContext | undefined, ...arrParams:any[] ):any;
}

function _ConvertFrom_CallbackImplementation( hCallbackImplementation:CallbackImplementation ):NativeCallbackImplementation {
    return function( ...arrParams:any[] ):any {
        let hContext:InvokeContext | undefined = undefined;
        if ( this != undefined )
            hContext = _ConvertTo_InvokeContext( this );
        return hCallbackImplementation.apply( hContext, arrParams );
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FunctionPtr Type Casts
function _TypeCastParamValue( mValue:FunctionParamValue ):NativeArgumentValue {
    if ( mValue instanceof Integer64 || mValue instanceof UInteger64 || mValue instanceof Pointer )
        return mValue.Handle;
    return mValue;
}
function _TypeCastReturnValue( mValue:NativeReturnValue ):FunctionReturnValue {
    if ( mValue instanceof Int64 ) return new Integer64( mValue );
    if ( mValue instanceof UInt64 ) return new UInteger64( mValue );
    if ( mValue instanceof NativePointer ) return new Pointer( mValue );
    return mValue;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The FunctionPtr class
class FunctionPtr extends Pointer
{
    // Getter
    get Handle():NativeFunction { return (this.m_hNativePointer as NativeFunction); }
    
    // Constructor
    constructor( ptrAddress:Pointer, strReturnType:FunctionSignatureType, arrArgumentTypes:FunctionSignatureType[], hOptions:FunctionPtrOptions | undefined ) {
        if ( hOptions != undefined ) {
            let hOpt:NativeFunctionOptions = _ConvertFrom_FunctionPtrOptions( hOptions );
            super( new NativeFunction(ptrAddress.Handle, strReturnType, arrArgumentTypes, hOpt) );
        } else
            super( new NativeFunction(ptrAddress.Handle, strReturnType, arrArgumentTypes) );
    }

    // Calling
    Apply( ptrThis:Pointer | undefined, arrParameters:FunctionParamValue[] ):FunctionReturnValue {
        let arrParams:NativeArgumentValue[] = [];
        arrParameters.forEach( function(hParam) {
            arrParams.push( _TypeCastParamValue(hParam) );
        });

        let mRetVal:NativeReturnValue = (this.m_hNativePointer as NativeFunction).apply (
            ( ptrThis != undefined ) ? ptrThis.Handle : undefined,
            arrParams
        );

        return _TypeCastReturnValue( mRetVal );
    }
    Call( ptrThis:Pointer | undefined, ...arrParameters:FunctionParamValue[] ):FunctionReturnValue {
        let arrParams:NativeArgumentValue[] = [];
        arrParameters.forEach( function(hParam) {
            arrParams.push( _TypeCastParamValue(hParam) );
        });

        let mRetVal:NativeReturnValue = (this.m_hNativePointer as NativeFunction).call (
            ( ptrThis != undefined ) ? ptrThis.Handle : undefined,
            arrParams
        );

        return _TypeCastReturnValue( mRetVal );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SystemFunctionPtr Type Casts
function _TypeCastSystemReturnValue( mValue:SystemFunctionResult ):FunctionSystemReturnValue {
    let mCasted:Partial<FunctionSystemReturnValue> = {};

    if ( mValue.value instanceof Int64 ) mCasted.Value = new Integer64( mValue.value );
    else if ( mValue.value instanceof UInt64 ) mCasted.Value = new UInteger64( mValue.value );
    else if ( mValue.value instanceof NativePointer ) mCasted.Value = new Pointer( mValue.value );
    else mCasted.Value = mValue.value;

    if ( (mValue as WindowsSystemFunctionResult).lastError != undefined )
        mCasted.Error = (mValue as WindowsSystemFunctionResult).lastError;
    else if ( (mValue as UnixSystemFunctionResult).errno != undefined )
        mCasted.Error = (mValue as UnixSystemFunctionResult).errno;
    
    return ( mCasted as FunctionSystemReturnValue );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The SystemFunctionPtr class
class SystemFunctionPtr extends Pointer
{
    // Getter
    get Handle():SystemFunction { return (this.m_hNativePointer as SystemFunction); }
    
    // Constructor
    constructor( ptrAddress:Pointer, strReturnType:FunctionSignatureType, arrArgumentTypes:FunctionSignatureType[], hOptions:FunctionPtrOptions | undefined ) {
        if ( hOptions != undefined ) {
            let hOpt:NativeFunctionOptions = _ConvertFrom_FunctionPtrOptions( hOptions );
            super( new SystemFunction(ptrAddress.Handle, strReturnType, arrArgumentTypes, hOpt) );
        } else
            super( new SystemFunction(ptrAddress.Handle, strReturnType, arrArgumentTypes) );
    }

    // Calling
    Apply( ptrThis:Pointer | undefined, arrParameters:FunctionParamValue[] ):FunctionSystemReturnValue {
        let arrParams:NativeArgumentValue[] = [];
        arrParameters.forEach( function(hParam) {
            arrParams.push( _TypeCastParamValue(hParam) );
        });

        let mRetVal:SystemFunctionResult = (this.m_hNativePointer as SystemFunction).apply (
            ( ptrThis != undefined ) ? ptrThis.Handle : undefined,
            arrParams
        );

        return _TypeCastSystemReturnValue( mRetVal );
    }
    Call( ptrThis:Pointer | undefined, ...arrParameters:FunctionParamValue[] ):FunctionSystemReturnValue {
        let arrParams:NativeArgumentValue[] = [];
        arrParameters.forEach( function(hParam) {
            arrParams.push( _TypeCastParamValue(hParam) );
        });

        let mRetVal:SystemFunctionResult = (this.m_hNativePointer as SystemFunction).call (
            ( ptrThis != undefined ) ? ptrThis.Handle : undefined,
            arrParams
        );

        return _TypeCastSystemReturnValue( mRetVal );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The CallBackFunctionPtr class
class CallBackFunctionPtr extends Pointer
{
    // Getter
    get Handle():NativeCallback { return (this.m_hNativePointer as NativeCallback); }
    
    // Constructor
    constructor( hCallbackImplementation:CallbackImplementation, strReturnType:FunctionSignatureType, arrArgumentTypes:FunctionSignatureType[],
                 strCallingConvention:CallingConvention | undefined ) {
        super( new NativeCallback(_ConvertFrom_CallbackImplementation(hCallbackImplementation), strReturnType, arrArgumentTypes, strCallingConvention) );
    }
}

