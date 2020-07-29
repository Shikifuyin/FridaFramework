////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Process/Process.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Process Management
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { AccessFlag } from "./Memory";

import { Pointer } from "../Native/Pointer";
import { CPUContext, _ConvertTo_CPUContext } from "../Native/CPUContext";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    ExceptionType,
    ExceptionDescriptor,
    ExceptionHandler,

    AllowsUnsignedCode,
    HasDebuggerAttached,
    GetPID,

    RegisterExceptionHandler,
    UnregisterExceptionHandler,

    APIResolverType,
    APIResolverResult,
    APIResolver,

    DebugSymbolData
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Process Interfaces : Exception handler
enum ExceptionType {
	Abort =              'abort',
	AccessViolation =    'access-violation',
	GuardPage =          'guard-page',
	IllegalInstruction = 'illegal-instruction',
	StackOverflow =      'stack-overflow',
	Arithmetic =         'arithmetic',
	Breakpoint =         'breakpoint',
	SingleStep =         'single-step',
	System =             'system'
};

interface ExceptionDescriptor {
    Type:ExceptionType;
    Address:Pointer;
    Operation?:AccessFlag;
    OperationAddress?:Pointer;
    Context:CPUContext;
    NativeContext:Pointer; // Last resort only ! When CPUContext is not enough ...
}
interface ExceptionHandler {
    // Return true to resume thread immediately
    // Return false to forward to hosting process / OS
    ( hDescriptor:ExceptionDescriptor ):boolean;
}

function _ConvertFrom_ExceptionHandler( hExceptionHandler:ExceptionHandler ):ExceptionHandlerCallback {
    return function( hDetails:ExceptionDetails ):boolean | void {
        let hConverted:Partial<ExceptionDescriptor> = {};
        hConverted.Type = ExceptionType[hDetails.type as keyof typeof ExceptionType];
        hConverted.Address = new Pointer( hDetails.address );

        hConverted.Operation = undefined;
        hConverted.OperationAddress = undefined;
        if ( hDetails.memory != undefined ) {
            switch( hDetails.memory.operation ) {
                case "read":    hConverted.Operation = AccessFlag.Read; break;
                case "write":   hConverted.Operation = AccessFlag.Write; break;
                case "execute": hConverted.Operation = AccessFlag.Execute; break;
            }
            hConverted.OperationAddress = new Pointer( hDetails.memory.address );
        }

        hConverted.Context = _ConvertTo_CPUContext( hDetails.context );
        hConverted.NativeContext = new Pointer( hDetails.nativeContext );

        if ( hExceptionHandler(hConverted as ExceptionDescriptor) )
            return true;
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Process properties
function AllowsUnsignedCode():boolean {
    return ( Process.codeSigningPolicy == 'optional' );
}
function HasDebuggerAttached():boolean {
    return Process.isDebuggerAttached();
}

function GetPID():number {
    return Process.id;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Process Exception handler
function RegisterExceptionHandler( hHandler:ExceptionHandler ):void {
    Process.setExceptionHandler( _ConvertFrom_ExceptionHandler(hHandler) );
}
function UnregisterExceptionHandler() {
    Process.setExceptionHandler( function( hDetails:ExceptionDetails ):boolean | void {
        // do nothing
    });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// API Resolver
const enum APIResolverType {
    Modules    = 'module',
    ObjectiveC = 'objc' // MacOS / iOS only
};

interface APIResolverResult {
    Name:string;
    Address:Pointer;
}

class APIResolver {
    // Members
    private m_hApiResolver:ApiResolver;

    // Getter
	get Handle():ApiResolver { return this.m_hApiResolver; }

	// Constructor
	constructor( strType:APIResolverType = APIResolverType.Modules ) {
		this.m_hApiResolver = new ApiResolver( strType );
    }
    
    // Queries can use wildcards '*'
    // Can prefix by 'imports:' or 'exports:'
    // Can suffix with '/i' for case-insensitive search
    Query( strQuery:string ):APIResolverResult[] {
        let arrDescs:ApiResolverMatch[] = this.m_hApiResolver.enumerateMatches( strQuery );

        let arrResults:APIResolverResult[] = [];
        arrDescs.forEach( function(hDesc:ApiResolverMatch):void {
            arrResults.push({
                Name: hDesc.name,
                Address : new Pointer( hDesc.address )
            });
        });
        return arrResults;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Debug Symbols
class DebugSymbolData {
    // Members
    private m_hDebugSymbol:DebugSymbol;

    // Getter
	get Handle():DebugSymbol { return this.m_hDebugSymbol; }

    // constructor
    constructor( hDebugSymbol:DebugSymbol ) {
        this.m_hDebugSymbol = hDebugSymbol;
    }
    static FromAddress( ptrAddress:Pointer ):DebugSymbolData {
        return new DebugSymbolData( DebugSymbol.fromAddress(ptrAddress.Handle) );
    }
    static FromName( strName:string ):DebugSymbolData {
        return new DebugSymbolData( DebugSymbol.fromName(strName) );
    }

    // Convert
    toString():string { return this.m_hDebugSymbol.toString(); }

    // Properties
    GetAddress():Pointer          { return new Pointer(this.m_hDebugSymbol.address); }
    GetName():string | null       { return this.m_hDebugSymbol.name; }
    GetModuleName():string | null { return this.m_hDebugSymbol.moduleName; }
    GetFileName():string | null   { return this.m_hDebugSymbol.fileName; }
    GetLineNumber():number | null { return this.m_hDebugSymbol.lineNumber; }

    // Methods
    static GetFunctionByName( strName:string ):Pointer {
        return new Pointer( DebugSymbol.getFunctionByName(strName) );
    }
    static ResolveFunctions( strName:string ):Pointer[] {
        let arrPtrs:NativePointer[] = DebugSymbol.findFunctionsNamed( strName );

        let arrResults:Pointer[] = [];
        arrPtrs.forEach( function(hPtr):void {
            arrResults.push( new Pointer(hPtr) );
        });
        return arrResults;
    }
    static ResolveFunctionsMatching( strPattern:string ):Pointer[] {
        let arrPtrs:NativePointer[] = DebugSymbol.findFunctionsMatching( strPattern );

        let arrResults:Pointer[] = [];
        arrPtrs.forEach( function(hPtr):void {
            arrResults.push( new Pointer(hPtr) );
        });
        return arrResults;
    }

    static LoadModule( strModulePath:string ):void {
        DebugSymbol.load( strModulePath );
    }
}
