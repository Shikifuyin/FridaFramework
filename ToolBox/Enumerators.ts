////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./ToolBox/Enumerators.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Common All-Purpose Enumerators
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import * as FridaLib from '../FridaLib/FridaLib';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    EnumClasses,
    EnumInstances,
    EnumNativeMethods
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Classes Enumerator
function EnumClasses( strPattern:string ):void
{
    // Say Hello
    FridaLib.Log.Info( "[EnumClasses] Starting enumeration (pattern='" + strPattern + "') ..." );

    // Enumerate all loaded classes
    let iMatchCount:number = 0;
    
    FridaLib.Java.EnumClasses({
        
        OnMatch: function( strClassName:string, ptrAddress:FridaLib.Native.Pointer ):void {
            // Filter out
            let bMatched:boolean = strClassName.includes( strPattern );
            if ( !bMatched ) {
                return;
            }
            
            FridaLib.Log.Info( "[EnumClasses] Found matching class : " + strClassName, FridaLib.Log.Color.LightGreen );
            
            // Count
            ++iMatchCount;
        },
        
        OnComplete: function():void {
            FridaLib.Log.Info( "[EnumClasses] Done, found " + iMatchCount + " matching classes !" );
        }
        
    });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Instances Enumerator
function EnumInstances( strClassName:string ):void
{
    // Say Hello
    FridaLib.Log.Info( "[EnumInstances] Starting enumeration (class='" + strClassName + "') ..." );

    // Scan Memory for instances
    let iMatchCount:number = 0;
    
    FridaLib.Java.EnumInstances( strClassName, {
        
        OnMatch: function( hInstance ):boolean {
            FridaLib.Log.Info( "[EnumInstances] Found instance at address : " + hInstance, FridaLib.Log.Color.LightGreen );
            FridaLib.Log.Info( "[EnumInstances] -> Object Content :", FridaLib.Log.Color.LightBlue );
            FridaLib.Log.Info( hInstance, FridaLib.Log.Color.LightBlue );
            
            // Count
            ++iMatchCount;

            // Continue
            return true;
        },
        
        OnComplete: function() {
            FridaLib.Log.Info( "[EnumInstances] Done, found " + iMatchCount + " matching instances !" );
        }
        
    });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Native Methods Enumerator
function EnumNativeMethods():void
{
    // Say Hello
    FridaLib.Log.Info( "[EnumNativeMethods] Starting enumeration ..." );

    // Get pointer size
    const iPointerSize:number = FridaLib.Memory.GetPointerSize();
    
    // See https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
    const iFindClassIndex:number = 6;         // jclass FindClass(JNIEnv *env, const char *name);
    const iRegisterNativesIndex:number = 215; // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
    
    // Environment allows to recover native addresses
    let hJNIEnv = FridaLib.Java.GetJNIEnv();
    function GetNativeAddress( iIndex:number ):FridaLib.Native.Pointer {
        return new FridaLib.Native.Pointer( hJNIEnv.handle.readPointer().add(iIndex * iPointerSize).readPointer() );
    }
    
    // Build a mapping
    interface AddressToNameMap {
        [Address:string]:string;
    }
    let mapAddressToName:AddressToNameMap = {};

    // Intercept FindClass calls to populate our map
    FridaLib.Interceptor.Attach( GetNativeAddress(iFindClassIndex), {
        _type: FridaLib.Interceptor.ListenerCallbackType.Script,

        OnEnter: function( arrArgs:FridaLib.Native.Pointer[] ):void {
            // args[0] -> JNIEnv * env
            // args[1] -> const char * name
            let strName:string | null = arrArgs[1].ReadString( FridaLib.Native.StringEncoding.ASCII );
            if ( strName == null )
                return;

            // JNIEnv * -> jclass name
            FridaLib.Log.Info( "[EnumNativeMethods] Intercepted jclass : " + strName, FridaLib.Log.Color.LightGreen );
            mapAddressToName[arrArgs[0].toString()] = strName;
        }
    });
    
    // Intercept RegisterNatives calls
    FridaLib.Interceptor.Attach( GetNativeAddress(iRegisterNativesIndex), {
        _type: FridaLib.Interceptor.ListenerCallbackType.Script,

        OnEnter: function( arrArgs:FridaLib.Native.Pointer[] ) {
            // args[0] -> JNIEnv * env
            // args[1] -> jclass clazz
            // args[2] -> const JNINativeMethod * methods
            // args[3] -> jint nMethods
            let strJClassName:string = mapAddressToName[arrArgs[0].toString()];
            let ptrMethods = new FridaLib.Native.Pointer( arrArgs[2] );
            let iMethodCount:number = parseInt( arrArgs[3].toString() );
            
            // JNINativeMethod struct
            //typedef struct {
            //	const char * name;
            //	const char * signature;
            //	void * fnPtr;
            //} JNINativeMethod;
            let iStructSize:number      = 3 * iPointerSize; // sizeof(JNINativeMethod)
            let iNameOffset:number      = 0;
            let iSignatureOffset:number = iPointerSize;
            let iFnPtrOffset:number     = 2 * iPointerSize;
            
            // Parse jclass name
            let arrJClassNameElements:string[] = strJClassName.split('/');
            let strPackageName:string = arrJClassNameElements.slice(0,-1).join('.');
            let strClassName:string = arrJClassNameElements[arrJClassNameElements.length - 1];
            
            // Enum all methods
            for( let i:number = 0; i < iMethodCount; ++i ) {
                let iMethodOffset:number = i * iStructSize;

                let ptrName:FridaLib.Native.Pointer      = ptrMethods.Add( iMethodOffset + iNameOffset );
                let ptrSignature:FridaLib.Native.Pointer = ptrMethods.Add( iMethodOffset + iSignatureOffset );
                let ptrFnPtr:FridaLib.Native.Pointer     = ptrMethods.Add( iMethodOffset + iFnPtrOffset );

                let strName:string | null          = ptrName.ReadPointer().ReadString( FridaLib.Native.StringEncoding.ASCII );
                let strSignature:string | null     = ptrSignature.ReadPointer().ReadString( FridaLib.Native.StringEncoding.ASCII );
                let pFnPtr:FridaLib.Native.Pointer = ptrFnPtr.ReadPointer();
                
                FridaLib.Log.Info( "[EnumNativeMethods] Intercepted method :", FridaLib.Log.Color.LightGreen );
                FridaLib.Log.Info(
                    {
                        module: FridaLib.Process.DebugSymbolData.FromAddress(pFnPtr).GetModuleName(),
                        package: strPackageName,
                        class: strClassName,
                        method: strName,
                        signature: strSignature, // Signature parser (JADX) : https://github.com/skylot/jadx/blob/master/jadx-core/src/main/java/jadx/core/dex/nodes/parser/SignatureParser.java
                        address: pFnPtr.toString()
                    },
                    FridaLib.Log.Color.LightBlue
                );
            }
        }
    });
}

