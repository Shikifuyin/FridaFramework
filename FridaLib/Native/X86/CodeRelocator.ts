////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/X86/CodeRelocator.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Relocator for X86 Architecture
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
// X86 CodeRelocator
class CodeRelocator
{
	// Members
	private m_hX86Relocator:X86Relocator;

	// Getter
	get Handle():X86Relocator { return this.m_hX86Relocator; }

	// Constructor
	constructor( ptrInputCode:Pointer, hCodeWriter:CodeWriter ) {
		this.m_hX86Relocator = new X86Relocator( ptrInputCode.Handle, hCodeWriter.Handle );
    }
    Reset( ptrInputCode:Pointer, hCodeWriter:CodeWriter ):void {
		this.m_hX86Relocator = new X86Relocator( ptrInputCode.Handle, hCodeWriter.Handle );
	}

	// Properties
	IsAtEndOfBlock():boolean { return this.m_hX86Relocator.eob; } // A Branch of any kind has been reached
	IsAtEndOfInput():boolean { return this.m_hX86Relocator.eoi; } // Code beyond may not be valid

	// Methods
	Cleanup():void { this.m_hX86Relocator.dispose(); }

	// Read instructions to internal buffer 
	ReadNext():number { return this.m_hX86Relocator.readOne(); } // returns number of bytes read so far

	GetLastInstructionRead():CPUInstruction | null {
        if ( this.m_hX86Relocator.input == null )
            return null;
        return new CPUInstruction( this.m_hX86Relocator.input as X86Instruction );
    }

	// Write buffered instructions
	WriteNext():void        { this.m_hX86Relocator.writeOne(); }
	WriteNextNoLabel():void { this.m_hX86Relocator.writeOneNoLabel(); } // When all branches are relocated (ie. Stalker)

	SkipNext():void        { this.m_hX86Relocator.skipOne(); }
	SkipNextNoLabel():void { this.m_hX86Relocator.skipOneNoLabel(); } // When all branches are relocated (ie. Stalker)

	WriteAll():void { this.m_hX86Relocator.writeAll(); }

	PeekNextWriteInstr():CPUInstruction | null {
        let tmpInstr:Instruction | null = this.m_hX86Relocator.peekNextWriteInsn();
        if ( tmpInstr == null )
            return null;
        return new CPUInstruction( tmpInstr as X86Instruction );
    }
	PeekNextWriteAddress():Pointer { return new Pointer( this.m_hX86Relocator.peekNextWriteSource() ); }
};
