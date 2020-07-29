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
};





// Methods, Options :
// -- 'method'       = (String) Method name, default = '$init'
// -- 'arguments'    = (Array of String) Argument types list, default = []
// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
// -- 'callOriginal' = (Boolean) Whether to call the original method, default = true
// -- 'argcallback'  = (function) Callback before original call, default = null
//                     Prototype = arrNewArgs function(strClassName, strMethodName, arrOriginalArgs, self);
// -- 'retcallback'  = (function) Callback after original call, default = null
//                     Prototype = hNewRetValue function(strClassName, strMethodName, arrEffectiveArgs, hOriginalRetValue, self);
static HookMethod( strClassName, arrOptions )
{
    // Parse options
    var strMethodName   = ( arrOptions['method'] !== undefined )       ? arrOptions['method'] : '$init';
    var arrArguments    = ( arrOptions['arguments'] !== undefined )    ? arrOptions['arguments'] : [];
    var bStackTrace     = ( arrOptions['stacktrace'] !== undefined )   ? arrOptions['stacktrace'] : false;
    var bCallOriginal   = ( arrOptions['callOriginal'] !== undefined ) ? arrOptions['callOriginal'] : true;
    var funcArgCallback = ( arrOptions['argcallback'] !== undefined )  ? arrOptions['argcallback'] : null;
    var funcRetCallback = ( arrOptions['retcallback'] !== undefined )  ? arrOptions['retcallback'] : null;
    
    // Say Hello
    FridaToolBox.Log.Info( "[HookMethod:INFO] Hooked " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrArguments) + ")" );
    
    // Get class handle
    var hClass = Java.use( strClassName );
    
    // Get overloaded method
    var hMethod = hClass[strMethodName].overload.apply( null, arrArguments );
    
    // Replace implementation
    hMethod.implementation = function() {
        // Retrieve original arguments as an array
        var arrOriginalArgs = [].slice.call( arguments );
        
        // Call start
        FridaToolBox.Log.Info( "[HookMethod:INFO] Call Start : " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrOriginalArgs) + ")", Color.Green );
        
        // Log stack trace
        if ( bStackTrace ) {
            FridaToolBox.Log.Info( "[HookMethod:INFO] ------- STACK TRACE BEGIN -------", Color.Blue );
            FridaToolBox.Trace.FromThread( this );
            FridaToolBox.Log.Info( "[HookMethod:INFO] -------- STACK TRACE END --------", Color.Blue );
        }
        
        // Raise callback
        var arrEffectiveArgs = null;
        if ( funcArgCallback != null ) {
            FridaToolBox.Log.Info( "[HookMethod:INFO] Raising arguments callback ...", Color.Blue );
            arrEffectiveArgs = funcArgCallback( strClassName, strMethodName, arrOriginalArgs );
        }
        
        // Call original function
        var hOriginalRetVal = null;
        if ( bCallOriginal ) {
            FridaToolBox.Log.Info( "[HookMethod:INFO] Calling original method ...", Color.Blue );
            hOriginalRetVal = this[strMethodName].apply( this, arrOriginalArgs, self );
            FridaToolBox.Log.Info( "[HookMethod:INFO] Original method returned : " + JSON.stringify(hResult), Color.Blue );
        }
        
        // Raise callback
        var hEffectiveRetVal = null;
        if ( funcRetCallback != null ) {
            FridaToolBox.Log.Info( "[HookMethod:INFO] Raising retval callback ...", Color.Blue );
            hEffectiveRetVal = funcRetCallback( strClassName, strMethodName, arrEffectiveArgs, hOriginalRetVal );
        }
        
        // Call end
        FridaToolBox.Log.Info( "[HookMethod:INFO] Call End, returning : " + JSON.stringify(hEffectiveRetVal), Color.Blue );
        
        // Done
        return hEffectiveRetVal;
    };
}

// Classes, Options :
// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
// -- 'callOriginal' = (Boolean) Whether to call the original method, default = true
// -- 'argcallback'  = (function) Callback before original call, default = null
//                     Prototype = arrNewArgs function(strClassName, strMethodName, arrOriginalArgs, self);
// -- 'retcallback'  = (function) Callback after original call, default = null
//                     Prototype = hNewRetValue function(strClassName, strMethodName, arrEffectiveArgs, hOriginalRetValue, self);
static HookClass( strClassName, arrOptions )
{
    // Say Hello
    FridaToolBox.Log.Info( "[HookClass:INFO] Hooking all methods from " + strClassName );
    
    // Get class handle
    var hClass = Java.use( strClassName );
    
    // Get all methods
    var arrMethods = hClass.class.getDeclaredMethods();
    hClass.$dispose();
    
    // Hook all methods
    arrMethods.forEach( function(hMethod) {
        // Get Method name
        var strMethodName = hMethod.getName();
        
        // Get Parameter Types names
        var arrParameterTypes = hMethod.getParameterTypes();
        var arrParameterTypeNames = [];
        arrParameterTypes.forEach( function(hParam) {
            arrParameterTypeNames.push( hParam.getName() );
        });
        
        // Build Options
        arrHookMethodOptions = {
            method: strMethodName,
            arguments: arrParameterTypeNames,
            stacktrace: arrOptions['stacktrace'],
            callOriginal: arrOptions['callOriginal'],
            argcallback: arrOptions['argcallback'],
            retcallback: arrOptions['retcallback']
        };
        
        // Hook Method
        FridaToolBox.Hook.HookMethod( strClassName, arrHookMethodOptions );
    });
}

// Native Methods (JNI), Options :
// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
// -- 'argcallback'  = (function) Callback before original call, default = null
//                     Prototype = function( arrArgs );
// -- 'retcallback'  = (function) Callback after original call, default = null
//                     Prototype = function( retValue );
// Obtaining address : $ nm --demangle --dynamic somelib.so | grep "SomeClass::SomeMethod("
static HookNativeMethod( strModuleName, iNativeMethodAddress, arrOptions )
{
    // Parse options
    var bStackTrace     = ( arrOptions['stacktrace'] !== undefined )  ? arrOptions['stacktrace'] : false;
    var funcArgCallback = ( arrOptions['argcallback'] !== undefined ) ? arrOptions['argcallback'] : null;
    var funcRetCallback = ( arrOptions['retcallback'] !== undefined ) ? arrOptions['retcallback'] : null;
    
    // Say Hello
    FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Hooked " + strModuleName + " - " + iNativeMethodAddress );
    
    // Intercept dlopen calls
    Interceptor.attach( Module.findExportByName(null, "dlopen"), {
        
        onEnter: function( dlopen_args ) {
            // Get library name
            this.libraryName = Memory.readUtf8String( dlopen_args[0] );
            FridaToolBox.Log.Info( "[HookNativeMethod:INFO] dlopen called for library : " + this.libraryName, Color.Green );
        },
        
        onLeave: function( dlopen_retval ) {
            // Filter module name
            var bMatch = this.libraryName.endsWith( strModuleName );
            if ( !bMatch )
                return;
            
            // Found a match
            FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Matched module name ! dlopen returned " + dlopen_retval, Color.Green );
            
            // Intercept Native method
            var iBaseAddress = Module.findBaseAddress( strModuleName );
            Interceptor.attach( iBaseAddress.add(iNativeMethodAddress), {
                
                onEnter: function( args ) {
                    FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Call Start ...", Color.Green );
                    
                    // Log stack trace
                    if ( bStackTrace ) {
                        FridaToolBox.Log.Info( "[HookNativeMethod:INFO] ------- STACK TRACE BEGIN -------", Color.Blue );
                        FridaToolBox.Trace.FromThread( this );
                        FridaToolBox.Log.Info( "[HookNativeMethod:INFO] -------- STACK TRACE END --------", Color.Blue );
                    }
                    
                    // Raise callback
                    if ( funcArgCallback != null ) {
                        FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Raising arguments callback ...", Color.Blue );
                        funcArgCallback( args );
                    }
                },
                
                onLeave: function( retval ) {
                    // Raise callback
                    if ( funcRetCallback != null ) {
                        FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Raising retval callback ...", Color.Blue );
                        funcRetCallback( retval );
                    }
                    
                    FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Call End ...", Color.Blue );
                }
                
            });
        }
        
    });
}