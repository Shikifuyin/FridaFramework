////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/CPUInstruction.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : CPUInstruction common to all Architectures
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { assert } from "console";

import { Pointer } from "./Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    BaseCPUInstruction
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BaseCPUInstruction Interfaces
type GenericInstruction = Instruction | X86Instruction | ArmInstruction | Arm64Instruction | MipsInstruction;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The BaseCPUInstruction class
class BaseCPUInstruction
{
    // Members
	protected m_hInstruction:GenericInstruction;

	// Getter
	get Handle():GenericInstruction { return this.m_hInstruction; }

    // Constructor
    constructor( hInstruction:GenericInstruction ) { this.m_hInstruction = hInstruction; }

    // Type
    IsX86():boolean   { return (this.m_hInstruction instanceof X86Instruction); }
    IsARM():boolean   { return (this.m_hInstruction instanceof ArmInstruction); }
    IsARM64():boolean { return (this.m_hInstruction instanceof Arm64Instruction); }
    IsMIPS():boolean  { return (this.m_hInstruction instanceof MipsInstruction); }

    // Convert
    toString():string { return this.m_hInstruction.toString(); }
    
    // Properties
	GetAddress():Pointer     { return new Pointer( this.m_hInstruction.address ); }
	GetNextAddress():Pointer { return new Pointer( this.m_hInstruction.next ); }
	GetSize():number         { return this.m_hInstruction.size; }
	GetMnemonic():string     { return this.m_hInstruction.mnemonic; }

    GetOperandsString():string { return this.m_hInstruction.opStr; }
    
    GetGroupCount():number { return this.m_hInstruction.groups.length; }
	GetGroup( iIndex:number ):string {
        assert( iIndex < this.m_hInstruction.groups.length );
        return this.m_hInstruction.groups[iIndex];
    }
}

