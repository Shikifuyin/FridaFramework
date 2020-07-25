////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Process/Module.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Module Management
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Native/Pointer";

import { Range, _ConvertTo_Range, _ConvertTo_AccessFlags, _ConvertFrom_AccessFlags } from "../Memory/Memory";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    ImportDescriptor,

	ExportDescriptor,

	SymbolType,
	SymbolDescriptor,

	ModuleFilter,

	GetExportAddress,
	
	ModuleHandle,

	GetApplicationModule,
	GetModuleByAddress,
	GetModuleByName,
	EnumModules,
	GetBaseAddress,

	Load,
	EnsureInit,

	ModuleAddressMap
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Interfaces : Imports
interface ImportDescriptor {
    Name:string; // Only field to be guaranteed by Frida's backend !
    ModuleName?:string;
    Address?:Pointer;
    Storage?:Pointer;
    IsVariable?:boolean;
    IsFunction?:boolean;
}

function _ConvertTo_ImportDescriptor( hDetails:ModuleImportDetails ):ImportDescriptor {
	let hConverted:Partial<ImportDescriptor> = {};
	hConverted.Name = hDetails.name;
	hConverted.ModuleName = hDetails.module;

	hConverted.Address = undefined;
	if ( hDetails.address != undefined )
		hConverted.Address = new Pointer( hDetails.address );

	hConverted.Storage = undefined;
	if ( hDetails.slot != undefined )
		hConverted.Storage = new Pointer( hDetails.slot );

	hConverted.IsVariable = ( hDetails.type == "variable" );
	hConverted.IsFunction = ( hDetails.type == "function" );

	return ( hConverted as ImportDescriptor );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Interfaces : Exports
interface ExportDescriptor {
	Name:string;
	Address:Pointer;
	IsVariable:boolean;
    IsFunction:boolean;
}

function _ConvertTo_ExportDescriptor( hDetails:ModuleExportDetails ):ExportDescriptor {
	let hConverted:Partial<ExportDescriptor> = {};
	hConverted.Name = hDetails.name;
	hConverted.Address = new Pointer( hDetails.address );
	hConverted.IsVariable = ( hDetails.type == "variable" );
	hConverted.IsFunction = ( hDetails.type == "function" );

	return ( hConverted as ExportDescriptor );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Interfaces : Symbols
enum SymbolType {
	Unknown =           'unknown',
	Section =           'section',
		// ELF (Win32, UNIX)
	Common =            'common',
	Function =          'function',
	Object =            'object',
	File =              'file',
	TLS =               'tls',
		// Mach-O (MacOS)
	Undefined =         'undefined',
	UndefinedPrebound = 'prebound-undefined',
	Absolute =  	    'absolute',
	Indirect =  	    'indirect'
};

interface SymbolDescriptor {
	Name:string;
	Address:Pointer;
	Size?:number;
	IsGlobal:boolean;
	Type:SymbolType;
	SectionID?:string; // r2 format
	SectionAccessFlags?:number; // AccessFlags
}

function _ConvertTo_SymbolDescriptor( hDetails:ModuleSymbolDetails ):SymbolDescriptor {
	let hConverted:Partial<SymbolDescriptor> = {};
	hConverted.Name = hDetails.name;
	hConverted.Address = new Pointer( hDetails.address );
	hConverted.Size = hDetails.size;
	hConverted.IsGlobal = hDetails.isGlobal;
	hConverted.Type = SymbolType[hDetails.type as keyof typeof SymbolType];

	hConverted.SectionID = undefined;
	hConverted.SectionAccessFlags = undefined;
	if ( hDetails.section != undefined ) {
		hConverted.SectionID = hDetails.section.id;
		hConverted.SectionAccessFlags = _ConvertTo_AccessFlags( hDetails.section.protection );
	}

	return ( hConverted as SymbolDescriptor );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Interfaces : Mapping
interface ModuleFilter {
	(hModule:ModuleHandle):boolean;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Exports
function GetExportAddress( strExportName:string, strModuleName:string | null = null, bThrowException:boolean = false ):Pointer {
	if ( bThrowException )
		return new Pointer( Module.getExportByName(strModuleName, strExportName) );
	else {
		let ptrModule:NativePointer | null = Module.findExportByName( strModuleName, strExportName );
		if ( ptrModule == null )
			return Pointer.NULL;
		return new Pointer( ptrModule );
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Handle
class ModuleHandle {
    // Members
    private m_hModule:Module;

    // Getter
	get Handle():Module { return this.m_hModule; }

	// Constructor
	constructor( hModule:Module ) { this.m_hModule = hModule; }
    
    // Properties
    GetName():string         { return this.m_hModule.name; }
    GetPath():string         { return this.m_hModule.path; }
    GetBaseAddress():Pointer { return new Pointer( this.m_hModule.base ); }
    GetSize():number         { return this.m_hModule.size; }

    // Imports
    EnumImports():ImportDescriptor[] {
		let arrDescs:ModuleImportDetails[] = this.m_hModule.enumerateImports();

		let arrResults:ImportDescriptor[] = [];
		arrDescs.forEach( function( hDesc:ModuleImportDetails ):void {
            arrResults.push( _ConvertTo_ImportDescriptor(hDesc) );
        });
		return arrResults;
	}

    // Exports
    EnumExports():ExportDescriptor[] {
		let arrDescs:ModuleExportDetails[] = this.m_hModule.enumerateExports();

		let arrResults:ExportDescriptor[] = [];
		arrDescs.forEach( function( hDesc:ModuleExportDetails ):void {
            arrResults.push( _ConvertTo_ExportDescriptor(hDesc) );
        });
		return arrResults;
    }
    
    GetExportAddressByName( strName:string, bThrowException:boolean = false ):Pointer {
		if ( bThrowException )
			return new Pointer( this.m_hModule.getExportByName(strName) );
		else {
            let ptrExport:NativePointer | null = this.m_hModule.findExportByName( strName );
            return ( ptrExport != null ) ? new Pointer(ptrExport) : Pointer.NULL;
        }
	}

	// Symbols
	EnumSymbols() {
		let arrDescs:ModuleSymbolDetails[] = this.m_hModule.enumerateSymbols();

		let arrResults:SymbolDescriptor[] = [];
		arrDescs.forEach( function( hDesc:ModuleSymbolDetails ):void {
            arrResults.push( _ConvertTo_SymbolDescriptor(hDesc) );
        });
		return arrResults;
	}

	// Memory Ranges
	EnumMemoryRanges( iAccess:number, bCoalesce:boolean = false ):Range[] {
		let strProtection:string = _ConvertFrom_AccessFlags( iAccess );
		let arrDescs:RangeDetails[] = this.m_hModule.enumerateRanges( strProtection );

		let arrRanges:Range[] = [];
		arrDescs.forEach( function( hDesc:RangeDetails ):void {
			arrRanges.push( _ConvertTo_Range(hDesc) );
		});
		return arrRanges;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Enumeration
function GetApplicationModule():ModuleHandle {
	return new ModuleHandle( Process.enumerateModules()[0] );
}

function GetModuleByAddress( ptrAddress:Pointer, bThrowException:boolean = false ):ModuleHandle | null {
    if ( bThrowException )
        return new ModuleHandle( Process.getModuleByAddress(ptrAddress.Handle) );
	else {
		let hModule:Module | null = Process.findModuleByAddress( ptrAddress.Handle );
		if ( hModule == null )
			return null;
		return new ModuleHandle( hModule );
	}
}
function GetModuleByName( strName:string, bThrowException:boolean = false ):ModuleHandle | null {
    if ( bThrowException )
        return new ModuleHandle( Process.getModuleByName(strName) );
	else {
		let hModule:Module | null = Process.findModuleByName( strName );
		if ( hModule == null )
			return null;
		return new ModuleHandle( hModule );
	}
}

function EnumModules():ModuleHandle[] {
	let arrModules:Module[] = Process.enumerateModules();

	let arrResults:ModuleHandle[] = [];
	arrModules.forEach( function(hModule:Module):void {
		arrResults.push( new ModuleHandle(hModule) );
	});
	return arrResults;
}

function GetBaseAddress( strName:string, bThrowException:boolean = false ):Pointer {
	if ( bThrowException )
		return new Pointer( Module.getBaseAddress(strName) );
	else {
		let ptrModule:NativePointer | null = Module.findBaseAddress( strName );
		if ( ptrModule == null )
			return Pointer.NULL;
		return new Pointer( ptrModule );
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Loading
function Load( strPath:string ):ModuleHandle {
	return new ModuleHandle( Module.load(strPath) );
}
function EnsureInit( strName:string ):void {
	Module.ensureInitialized( strName );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Module Mapping
class ModuleAddressMap {
	// Members
    private m_hModuleMap:ModuleMap;

    // Getter
	get Handle():ModuleMap { return this.m_hModuleMap; }

	// Constructor
	constructor( hModuleMapFilter:ModuleFilter | undefined ) {
		if ( hModuleMapFilter == undefined )
			this.m_hModuleMap = new ModuleMap();
		else {
			this.m_hModuleMap = new ModuleMap( function(hModule:Module):boolean {
				return hModuleMapFilter( new ModuleHandle(hModule) );
			});
		}
	}
	
	Update():void { this.m_hModuleMap.update(); }
    
	// Methods
	HasAddress( ptrAddress:Pointer ):boolean { return this.m_hModuleMap.has(ptrAddress.Handle); }

	GetArray():ModuleHandle[] {
		let arrModules:Module[] = this.m_hModuleMap.values();

		let arrResults:ModuleHandle[] = [];
		arrModules.forEach( function(hModule:Module):void {
			arrResults.push( new ModuleHandle(hModule) );
		});
		return arrResults;
	}

	GetModule( ptrAddress:Pointer, bThrowException:boolean = false ):ModuleHandle | null {
		if ( bThrowException )
			return new ModuleHandle( this.m_hModuleMap.get(ptrAddress.Handle) );
		else {
			let hModule:Module | null = this.m_hModuleMap.find( ptrAddress.Handle );
			if ( hModule == null )
				return null;
			return new ModuleHandle( hModule );
		}
	}
	GetModuleName( ptrAddress:Pointer, bThrowException:boolean = false ):string | null {
		if ( bThrowException )
			return this.m_hModuleMap.getName( ptrAddress.Handle );
		else
			return this.m_hModuleMap.findName( ptrAddress.Handle );
	}
	GetModulePath( ptrAddress:Pointer, bThrowException:boolean = false ):string | null {
		if ( bThrowException )
			return this.m_hModuleMap.getPath( ptrAddress.Handle );
		else
			return this.m_hModuleMap.findPath( ptrAddress.Handle );
	}
}

