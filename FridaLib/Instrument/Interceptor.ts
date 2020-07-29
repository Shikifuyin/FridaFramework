////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Instrument/Interceptor.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Instrumentation : Interceptor
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Native/Pointer";
import { InvokeContext, _ConvertTo_InvokeContext } from "../Native/FunctionPtr";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    InvokeReturnValue,
    InvokeListener,

    ListenerCallbackType,
    ScriptListenerCallback,
    NativeListenerCallback,
    ProbeListenerCallback,
    ListenerCallback,

    Attach,
    DetachAll,

    Replace,
    Revert,

    Flush
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interceptor Interfaces : Invocation
class InvokeReturnValue extends Pointer {
    get Handle():InvocationReturnValue { return (this.m_hNativePointer as InvocationReturnValue); }
    constructor( hInvocationReturnValue:InvocationReturnValue ) { super( hInvocationReturnValue ); }

    Replace( ptrReturnValue:Pointer ):void {
        (this.m_hNativePointer as InvocationReturnValue).replace( ptrReturnValue.Handle );
    }
}

class InvokeListener {
    private m_hInvocationListener:InvocationListener;
    get Handle():InvocationListener { return this.m_hInvocationListener; }
    constructor( hInvocationListener:InvocationListener ) { this.m_hInvocationListener = hInvocationListener; }

    Detach():void { this.m_hInvocationListener.detach(); }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interceptor Interfaces : Callbacks
const enum ListenerCallbackType {
    Script = 'Script',
    Native = 'Native',
    Probe  = 'Probe',
};

interface ScriptListenerCallback {
    _type:ListenerCallbackType.Script;
    OnEnter?( this:InvokeContext, arrParams:Pointer[] ):void;
    OnLeave?( this:InvokeContext, retValue:InvokeReturnValue ):void;
}
interface NativeListenerCallback {
    _type:ListenerCallbackType.Native;
    // Native.C.Code : void onEnter( GumInvocationContext  * ic );
    OnEnter?:Pointer;
    // Native.C.Code : void onLeave( GumInvocationContext  * ic );
    OnLeave?:Pointer;
    // Native.C.Code : Use gum_invocation_context_get_listener_function_data() to obtain UserData
}
interface ProbeListenerCallback {
    _type:ListenerCallbackType.Probe;
    ( this:InvokeContext, arrParams:Pointer[] ):void;
}

type ListenerCallback = ScriptListenerCallback | NativeListenerCallback | ProbeListenerCallback;

function _ConvertFrom_ListenerCallback( hListenerCallback:ListenerCallback ):InvocationListenerCallbacks | InstructionProbeCallback {
    switch( hListenerCallback._type ) {
        case ListenerCallbackType.Script: {
            let hConverted:ScriptInvocationListenerCallbacks = {};

            hConverted.onEnter = undefined;
            if ( hListenerCallback.OnEnter != undefined ) {
                hConverted.onEnter = function( arrParameters:NativePointer[] ):void {
                    if ( hListenerCallback.OnEnter != undefined ) {
                        let arrParams:Pointer[] = [];
                        arrParameters.forEach( function(hParam:NativePointer) {
                            arrParams.push( new Pointer(hParam) );
                        });
                        
                        let hContext:InvokeContext = _ConvertTo_InvokeContext( this );
                        hListenerCallback.OnEnter.apply( hContext, [arrParams] );
                    }
                };
            }

            hConverted.onLeave = undefined;
            if ( hListenerCallback.OnLeave != undefined ) {
                hConverted.onLeave = function( returnValue:InvocationReturnValue ):void {
                    if ( hListenerCallback.OnLeave != undefined ) {
                        let retValue:InvokeReturnValue = new InvokeReturnValue( returnValue );
                        
                        let hContext:InvokeContext = _ConvertTo_InvokeContext( this );
                        hListenerCallback.OnLeave.apply( hContext, [retValue] );
                    }
                };
            }

            return hConverted;
        }
        case ListenerCallbackType.Native: {
            let hConverted:NativeInvocationListenerCallbacks = {};

            hConverted.onEnter = undefined;
            if ( hListenerCallback.OnEnter != undefined )
                hConverted.onEnter = hListenerCallback.OnEnter.Handle;
            
            hConverted.onLeave = undefined;
            if ( hListenerCallback.OnLeave != undefined )
                hConverted.onLeave = hListenerCallback.OnLeave.Handle;
            
            return hConverted;
        }
        case ListenerCallbackType.Probe: {
            return function( arrParameters:NativePointer[] ):void {
                let arrParams:Pointer[] = [];
                arrParameters.forEach( function(hParam:NativePointer) {
                    arrParams.push( new Pointer(hParam) );
                });

                let hContext:InvokeContext = _ConvertTo_InvokeContext( this );
                hListenerCallback.apply( hContext, [arrParams] );
            };
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interceptor Attach/Detach
function Attach( ptrTarget:Pointer, hCallBacks:ListenerCallback, ptrUserData:Pointer | undefined = undefined ):InvokeListener {
    let hCB:InvocationListenerCallbacks | InstructionProbeCallback = _ConvertFrom_ListenerCallback( hCallBacks );
    let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
    return new InvokeListener( Interceptor.attach(ptrTarget.Handle, hCB, ptrData) );
}
function DetachAll():void {
    Interceptor.detachAll();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interceptor Replace/Revert (Can use both Native.CallBackFunctionPtr or Native.C.Code !)
// Native C Code : gum_invocation_context_get_listener_function_data() to get ptrUserData
// Native C Code : gum_interceptor_get_current_invocation() to get a (GumInvocationContext *)
function Replace( ptrTarget:Pointer, ptrReplacement:Pointer, ptrUserData:Pointer | undefined = undefined ):void {
    let ptrData:NativePointer | undefined = ( ptrUserData != undefined ) ? ptrUserData.Handle : undefined;
    Interceptor.replace( ptrTarget.Handle, ptrReplacement.Handle, ptrData );
}
function Revert( ptrTarget:Pointer ):void {
    Interceptor.revert( ptrTarget.Handle );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interceptor Flush (needed if calling intercepted function right after interception)
function Flush():void {
    Interceptor.flush();
}

