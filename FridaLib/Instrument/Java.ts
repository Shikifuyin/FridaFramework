////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Instrument/Java.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Instrumentation : Java Environment
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Native/Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    ClassCallback,
    ClassLoaderCallback,
    ClassDeclaration,

    InstanceCallback,

    RunFunction,

    IsAvailable,
    GetAndroidVersion,
    DisableOptimization,
    
    EnumClasses,
    EnumClassNames,
    EnumClassLoaders,
    EnumClassLoadersSync,
    EnumMethods,
    GetClass,
    OpenDEXFile,
    CreateClass,
    GetClassFactory,

    EnumInstances,
    RetainInstance,
    CastInstance,
    MakeArray,

    Run,
    RunNow,
    IsMainThread,
    RunInMainThread,
    RunOnVM,
    GetJNIEnv
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Interfaces : Classes
interface ClassCallback {
    OnMatch?( strName:string, ptrHandle:Pointer ):void;
    OnComplete?():void;
}
interface ClassLoaderCallback {
    OnMatch?( hLoader:Java.Wrapper ):void;
    OnComplete?():void;
}
interface ClassDeclaration {
    Name:string;
    Extends?:Java.Wrapper;
    Implements?:Java.Wrapper[];
    Fields?: { [Name:string]:string };
    Methods?: { [Name:string]:Java.MethodImplementation | Java.MethodSpec | Java.MethodSpec[] };
}

function _ConvertFrom_ClassCallback( hClassCallback:ClassCallback ):Java.EnumerateLoadedClassesCallbacks {
    let hConverted:Partial<Java.EnumerateLoadedClassesCallbacks> = {};

    hConverted.onMatch = undefined;
    if ( hClassCallback.OnMatch != undefined ) {
        hConverted.onMatch = function( strName:string, ptrHandle:NativePointer ):void {
            if ( hClassCallback.OnMatch != undefined )
                hClassCallback.OnMatch( strName, new Pointer(ptrHandle) );
        };
    }

    hConverted.onComplete = hClassCallback.OnComplete;

    return ( hConverted as Java.EnumerateLoadedClassesCallbacks );
}
function _ConvertFrom_ClassLoaderCallback( hClassLoaderCallback:ClassLoaderCallback ):Java.EnumerateClassLoadersCallbacks {
    let hConverted:Partial<Java.EnumerateClassLoadersCallbacks> = {};

    hConverted.onMatch = hClassLoaderCallback.OnMatch;
    hConverted.onComplete = hClassLoaderCallback.OnComplete;

    return ( hConverted as Java.EnumerateClassLoadersCallbacks );
}
function _ConvertFrom_ClassDeclaration( hClassDeclaration:ClassDeclaration ):Java.ClassSpec {
    let hConverted:Partial<Java.ClassSpec> = {};

    hConverted.name = hClassDeclaration.Name;
    hConverted.superClass = hClassDeclaration.Extends;
    hConverted.implements = hClassDeclaration.Implements;
    hConverted.fields = hClassDeclaration.Fields;
    hConverted.methods = hClassDeclaration.Methods;

    return ( hConverted as Java.ClassSpec );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Interfaces : Instances
interface InstanceCallback {
    OnMatch?( hInstance:Java.Wrapper ):boolean; // return false to stop enumeration
    OnComplete?():void;
}

function _ConvertFrom_InstanceCallback( hInstanceCallback:InstanceCallback ):Java.ChooseCallbacks {
    let hConverted:Partial<Java.ChooseCallbacks> = {};

    hConverted.onMatch = undefined;
    if ( hInstanceCallback.OnMatch != undefined ) {
        hConverted.onMatch = function( hLoader:Java.Wrapper ):EnumerateAction | void {
            if ( hInstanceCallback.OnMatch != undefined ) {
                let bContinue:boolean = hInstanceCallback.OnMatch( hLoader );
                if ( !bContinue )
                    return "stop";
            }
        };
    }

    hConverted.onComplete = hInstanceCallback.OnComplete;

    return ( hConverted as Java.ChooseCallbacks );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Interfaces : Execution
interface RunFunction {
    ():void;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Properties
function IsAvailable():boolean {
    return Java.available;
}
function GetAndroidVersion():string {
    return Java.androidVersion;
}

function DisableOptimization() {
    Java.deoptimizeEverything();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Classes

// Loaded Classes
function EnumClasses( hCallbacks:ClassCallback ):void {
    Java.enumerateLoadedClasses( _ConvertFrom_ClassCallback(hCallbacks) );
}
function EnumClassNames():string[] {
    return Java.enumerateLoadedClassesSync();
}

// Class Loaders
function EnumClassLoaders( hCallbacks:ClassLoaderCallback ):void {
    Java.enumerateClassLoaders( _ConvertFrom_ClassLoaderCallback(hCallbacks) );
}
function EnumClassLoadersSync():Java.Wrapper[] {
    return Java.enumerateClassLoadersSync();
}

// Methods
// strQuery = "classname!methodname (/options)"
// option = /i - case insensitive
//          /s - include full signature
//          /u - user-defined classes only, ignore system classes
function EnumMethods( strQuery:string ):Java.EnumerateMethodsMatchGroup[] {
    return Java.enumerateMethods(strQuery);
}

// Class Wrappers
function GetClass( strClassName:string ):Java.Wrapper {
    return Java.use( strClassName );
}

// DEX files
function OpenDEXFile( strPath:string ):Java.DexFile {
    return Java.openClassFile( strPath );
}

// Class declaration
function CreateClass( hClassDeclaration:ClassDeclaration ):Java.Wrapper {
    return Java.registerClass( _ConvertFrom_ClassDeclaration(hClassDeclaration) );
}

// Class Factory
function GetClassFactory():Java.ClassFactory {
    return Java.classFactory;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Instances
function EnumInstances( strClassName:string, hCallbacks:InstanceCallback ):void {
    Java.choose( strClassName, _ConvertFrom_InstanceCallback(hCallbacks) );
}

function RetainInstance( hInstance:Java.Wrapper ):Java.Wrapper {
    return Java.retain( hInstance );
}
function CastInstance( hInstance:Pointer | Java.Wrapper, hClass:Java.Wrapper ):Java.Wrapper {
    if ( hInstance instanceof Pointer )
        return Java.cast( hInstance.Handle, hClass );
    return Java.cast( hInstance, hClass );
}

function MakeArray( strType:string, arrElements:any[] ):any[] {
    return Java.array( strType, arrElements );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Java Execution
function Run( funcRun:RunFunction ):void {
    Java.perform( funcRun );
}
function RunNow( funcRun:RunFunction ):void {
    Java.performNow( funcRun );
}

function IsMainThread():boolean {
    return Java.isMainThread();
}
function RunInMainThread( funcRun:RunFunction ) {
    Java.scheduleOnMainThread( funcRun );
}

function RunOnVM( funcRun:RunFunction ):void {
    Java.vm.perform( funcRun );
}

function GetJNIEnv( bThrowExceptions:boolean = false ):any {
    if ( bThrowExceptions )
        return Java.vm.tryGetEnv();
    else
        return Java.vm.getEnv();
}

