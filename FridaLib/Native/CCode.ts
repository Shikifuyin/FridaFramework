////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/CCode.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Native C Code compilation & injection
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "./Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    CodeSymbols,
    
    Code
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Code Interfaces : Symbols
interface CodeSymbols {
    [Name: string]:Pointer;
}

function _ConvertFrom_CodeSymbols( hCodeSymbols:CodeSymbols ):CSymbols {
    let hConverted:CSymbols = {};

    const arrKeys:string[] = Object.keys( hCodeSymbols );
    arrKeys.forEach( function( hSymbolKey:string ):void {
        hConverted[hSymbolKey] = hCodeSymbols[hSymbolKey].Handle;
    });
    
    return hConverted;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Code
// Global Functions in the C Code are exported as properties of CCode.
// All data is read-only !
// Writable data must be allocated using Memory.HeapAlloc/PageAlloc/StringAlloc,
// passed in as a symbol, and declared as 'extern' in the C Code.
// Symbols can also be FunctionPtr/CallBackFunctionPtr ...
// C Code can define the following special functions for init/cleanup :
// void init(void);
// void finalize(void);
class Code {
    // Members
	private m_hCModule:CModule;
	
	// Getter
	get Handle():CModule { return this.m_hCModule; }

	// Constructor
	constructor( strCode:string, hExternSymbols:CodeSymbols | undefined ) {
        if ( hExternSymbols == undefined )
		    this.m_hCModule = new CModule( strCode );
        else
            this.m_hCModule = new CModule( strCode, _ConvertFrom_CodeSymbols(hExternSymbols) );
    }
    
    // When waiting for garbage collection is not acceptable
    Destroy():void { this.m_hCModule.dispose(); }

    // Dynamic Properties
    GetFunction( strName:string ):Pointer {
        return new Pointer( this.m_hCModule[strName] as NativePointer );
    }
}
