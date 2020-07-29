////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./ToolBox/Hooks.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Common All-Purpose Hooks
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import * as FridaLib from '../FridaLib/FridaLib';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    HookMethodOptions,
    HookMethod,
    HookClass,

    HookNativeMethodOptions,
    HookNativeMethod
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Method Hook
interface HookMethodOptions {
    ShowStackTrace?:boolean; // Default = false
    CallOriginal?:boolean;   // Default = true
    Before?( strClassName:string, strMethodName:string, arrParams:any[] ):any[];             // Alter params here
    After?( strClassName:string, strMethodName:string, arrParams:any[], hRetValue:any ):any; // Alter return value here
}

function HookMethod( strClassName:string, strMethodName:string, arrParameterTypes:string[], hOptions:HookMethodOptions | undefined = undefined ):void
{
    // Say Hello
    FridaLib.Log.Info( "[HookMethod] Hooked " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrParameterTypes) + ")" );
    
    // Get class handle
    let hClass = FridaLib.Java.GetClass( strClassName );
    
    // Get overloaded method
    let hMethod = hClass[strMethodName].overload.apply( null, arrParameterTypes );
    
    // Replace implementation
    hMethod.implementation = function():any {
        // Retrieve original arguments as an array
        let arrOriginalArgs:any[] = [].slice.call( arguments );
        
        // Call start
        FridaLib.Log.Info( "[HookMethod] Call Start : " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrOriginalArgs) + ")",
                           FridaLib.Log.Color.Green );
        
        // Log stack trace
        if ( hOptions != undefined && hOptions.ShowStackTrace == true ) {
            FridaLib.Log.Info( "[HookMethod] ------- STACK TRACE BEGIN -------", FridaLib.Log.Color.Blue );
            FridaLib.Log.Info( FridaLib.Java.GetStackTrace(), FridaLib.Log.Color.Blue );
            FridaLib.Log.Info( "[HookMethod] -------- STACK TRACE END --------", FridaLib.Log.Color.Blue );
        }
        
        // Raise callback
        let arrEffectiveArgs:any[] = [];
        if ( hOptions != undefined && hOptions.Before != undefined ) {
            FridaLib.Log.Info( "[HookMethod] Raising arguments callback ...", FridaLib.Log.Color.Blue );
            arrEffectiveArgs = hOptions.Before( strClassName, strMethodName, arrOriginalArgs );
        }
        
        // Call original function
        let hOriginalRetVal:any = undefined;
        if ( hOptions == undefined || hOptions.CallOriginal != false ) {
            FridaLib.Log.Info( "[HookMethod] Calling original method ...", FridaLib.Log.Color.Blue );
            hOriginalRetVal = this[strMethodName].apply( this, arrOriginalArgs );
            FridaLib.Log.Info( "[HookMethod] Original method returned : " + JSON.stringify(hOriginalRetVal), FridaLib.Log.Color.Blue );
        }
        
        // Raise callback
        let hEffectiveRetVal:any = undefined;
        if ( hOptions != undefined && hOptions.After != undefined ) {
            FridaLib.Log.Info( "[HookMethod] Raising retval callback ...", FridaLib.Log.Color.Blue );
            hEffectiveRetVal = hOptions.After( strClassName, strMethodName, arrEffectiveArgs, hOriginalRetVal );
        }
        
        // Call end
        FridaLib.Log.Info( "[HookMethod] Call End, returning : " + JSON.stringify(hEffectiveRetVal), FridaLib.Log.Color.Blue );
        
        // Done
        return hEffectiveRetVal;
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Class Hook
function HookClass( strClassName:string, hOptions:HookMethodOptions | undefined = undefined ):void
{
    // Say Hello
    FridaLib.Log.Info( "[HookClass] Hooking all methods from " + strClassName );
    
    // Get class handle
    let hClass = FridaLib.Java.GetClass( strClassName );
    
    // Get all methods
    let arrMethods:any[] = hClass.class.getDeclaredMethods();
    hClass.$dispose();
    
    // Hook all methods
    arrMethods.forEach( function( hMethod ):void {
        // Get Method name
        let strMethodName:string = hMethod.getName();
        
        // Get Parameter Types names
        let arrParameterTypes:any[] = hMethod.getParameterTypes();
        let arrParameterTypeNames:string[] = [];
        arrParameterTypes.forEach( function(hParam):void {
            arrParameterTypeNames.push( hParam.getName() );
        });
        
        // Hook Method
        HookMethod( strClassName, strMethodName, arrParameterTypeNames, hOptions );
    });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Native Methods (JNI) Hook
interface HookNativeMethodOptions {
    ShowStackTrace?:boolean; // Default = false
    Before?( arrParams:FridaLib.Native.Pointer[] ):void;
    After?( hRetValue:FridaLib.Interceptor.InvokeReturnValue ):void;
}

// Obtaining address in cmdline : $ nm --demangle --dynamic somelib.so | grep "SomeClass::SomeMethod("
function HookNativeMethod( strModuleName:string, ptrMethodAddress:FridaLib.Native.Pointer, hOptions:HookNativeMethodOptions | undefined = undefined ):void
{
    // Say Hello
    FridaLib.Log.Info( "[HookNativeMethod] Hooked " + strModuleName + " - " + ptrMethodAddress );
    
    // Intercept dlopen calls
    FridaLib.Interceptor.Attach( FridaLib.Module.GetExportAddress("dlopen"), {
        _type: FridaLib.Interceptor.ListenerCallbackType.Script,

        OnEnter: function( dlopen_args:FridaLib.Native.Pointer[] ):void {
            // Get library name
            this.strLibraryName = dlopen_args[0].ReadString( FridaLib.Native.StringEncoding.UTF8 );
            FridaLib.Log.Info( "[HookNativeMethod] dlopen called for library : " + this.strLibraryName, FridaLib.Log.Color.Green );
        },
        
        OnLeave: function( dlopen_retval:FridaLib.Interceptor.InvokeReturnValue ):void {
            // Filter module name
            let bMatch:boolean = this.strLibraryName.endsWith( strModuleName );
            if ( !bMatch )
                return;
            
            // Found a match
            FridaLib.Log.Info( "[HookNativeMethod] Matched module name ! dlopen returned " + dlopen_retval, FridaLib.Log.Color.Green );
            
            // Intercept Native method
            let ptrBaseAddress:FridaLib.Native.Pointer = FridaLib.Module.GetBaseAddress( strModuleName );
            FridaLib.Interceptor.Attach( ptrBaseAddress.Add(ptrMethodAddress), {
                _type: FridaLib.Interceptor.ListenerCallbackType.Script,
                
                OnEnter: function( arrParams:FridaLib.Native.Pointer[] ):void {
                    FridaLib.Log.Info( "[HookNativeMethod] Call Start ...", FridaLib.Log.Color.Green );
                    
                    // Log stack trace
                    if ( hOptions != undefined && hOptions.ShowStackTrace ) {
                        FridaLib.Log.Info( "[HookNativeMethod] ------- STACK TRACE BEGIN -------", FridaLib.Log.Color.Blue );
                        FridaLib.Log.Info( FridaLib.Thread.BackTrace(this.Context), FridaLib.Log.Color.Blue );
                        FridaLib.Log.Info( "[HookNativeMethod] -------- STACK TRACE END --------", FridaLib.Log.Color.Blue );
                    }
                    
                    // Raise callback
                    if ( hOptions != undefined && hOptions.Before != undefined ) {
                        FridaLib.Log.Info( "[HookNativeMethod] Raising arguments callback ...", FridaLib.Log.Color.Blue );
                        hOptions.Before( arrParams );
                    }
                },
                
                OnLeave: function( hRetValue:FridaLib.Interceptor.InvokeReturnValue ):void {
                    // Raise callback
                    if ( hOptions != undefined && hOptions.After != undefined ) {
                        FridaLib.Log.Info( "[HookNativeMethod] Raising retval callback ...", FridaLib.Log.Color.Blue );
                        hOptions.After( hRetValue );
                    }
                    
                    FridaLib.Log.Info( "[HookNativeMethod] Call End ...", FridaLib.Log.Color.Blue );
                }
                
            });
        }
        
    });
}

