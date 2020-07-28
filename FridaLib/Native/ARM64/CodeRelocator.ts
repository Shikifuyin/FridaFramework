////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM64/CodeRelocator.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Relocator for ARM64 Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Pointer";

import { CPUInstruction } from "./CPUInstruction";
import { CodeWriter } from "./CodeWriter";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    CodeRelocator
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM64 CodeRelocator
class CodeRelocator
{
	// Members
	private m_hArm64Relocator:Arm64Relocator;

	// Getter
	get Handle():Arm64Relocator { return this.m_hArm64Relocator; }

	// Constructor
	constructor( ptrInputCode:Pointer, hCodeWriter:CodeWriter ) {
		this.m_hArm64Relocator = new Arm64Relocator( ptrInputCode.Handle, hCodeWriter.Handle );
    }
    Reset( ptrInputCode:Pointer, hCodeWriter:CodeWriter ):void {
		this.m_hArm64Relocator.reset( ptrInputCode.Handle, hCodeWriter.Handle );
	}

	// Properties
	IsAtEndOfBlock():boolean { return this.m_hArm64Relocator.eob; } // A Branch of any kind has been reached
	IsAtEndOfInput():boolean { return this.m_hArm64Relocator.eoi; } // Code beyond may not be valid

	// Methods
	Cleanup():void { this.m_hArm64Relocator.dispose(); }

	// Read instructions to internal buffer 
	ReadNext():number { return this.m_hArm64Relocator.readOne(); } // returns number of bytes read so far

	GetLastInstructionRead():CPUInstruction | null {
        if ( this.m_hArm64Relocator.input == null )
            return null;
        return new CPUInstruction( this.m_hArm64Relocator.input as Arm64Instruction );
    }

	// Write buffered instructions
	WriteNext():void { this.m_hArm64Relocator.writeOne(); }
	SkipNext():void  { this.m_hArm64Relocator.skipOne(); }
	
	WriteAll():void { this.m_hArm64Relocator.writeAll(); }

	PeekNextWriteInstr():CPUInstruction | null {
        let tmpInstr:Instruction | null = this.m_hArm64Relocator.peekNextWriteInsn();
        if ( tmpInstr == null )
            return null;
        return new CPUInstruction( tmpInstr as Arm64Instruction );
    }
	PeekNextWriteAddress():Pointer { return new Pointer( this.m_hArm64Relocator.peekNextWriteSource() ); }
}

