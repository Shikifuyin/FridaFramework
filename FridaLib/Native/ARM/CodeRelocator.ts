////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/ARM/CodeRelocator.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : ASM Code Relocator for ARM Architecture
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Pointer";

import { CPUInstruction } from "./CPUInstruction";
import { CodeWriterARM } from "./CodeWriter";
import { CodeWriterThumb } from "./CodeWriter";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    CodeRelocatorARM,
    CodeRelocatorThumb
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM CodeRelocatorARM
class CodeRelocatorARM
{
	// Members
	private m_hArmRelocator:ArmRelocator;

	// Getter
	get Handle():ArmRelocator { return this.m_hArmRelocator; }

	// Constructor
	constructor( ptrInputCode:Pointer, hCodeWriter:CodeWriterARM ) {
		this.m_hArmRelocator = new ArmRelocator( ptrInputCode.Handle, hCodeWriter.Handle );
    }
    Reset( ptrInputCode:Pointer, hCodeWriter:CodeWriterARM ):void {
		this.m_hArmRelocator.reset( ptrInputCode.Handle, hCodeWriter.Handle );
	}

	// Properties
	IsAtEndOfBlock():boolean { return this.m_hArmRelocator.eob; } // A Branch of any kind has been reached
	IsAtEndOfInput():boolean { return this.m_hArmRelocator.eoi; } // Code beyond may not be valid

	// Methods
	Cleanup():void { this.m_hArmRelocator.dispose(); }

	// Read instructions to internal buffer 
	ReadNext():number { return this.m_hArmRelocator.readOne(); } // returns number of bytes read so far

	GetLastInstructionRead():CPUInstruction | null {
        if ( this.m_hArmRelocator.input == null )
            return null;
        return new CPUInstruction( this.m_hArmRelocator.input as ArmInstruction );
    }

	// Write buffered instructions
	WriteNext():void { this.m_hArmRelocator.writeOne(); }
	SkipNext():void  { this.m_hArmRelocator.skipOne(); }
	
	WriteAll():void { this.m_hArmRelocator.writeAll(); }

	PeekNextWriteInstr():CPUInstruction | null {
        let tmpInstr:Instruction | null = this.m_hArmRelocator.peekNextWriteInsn();
        if ( tmpInstr == null )
            return null;
        return new CPUInstruction( tmpInstr as ArmInstruction );
    }
	PeekNextWriteAddress():Pointer { return new Pointer( this.m_hArmRelocator.peekNextWriteSource() ); }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARM CodeRelocatorThumb
class CodeRelocatorThumb
{
	// Members
	private m_hThumbRelocator:ThumbRelocator;

	// Getter
	get Handle():ThumbRelocator { return this.m_hThumbRelocator; }

	// Constructor
	constructor( ptrInputCode:Pointer, hCodeWriter:CodeWriterThumb ) {
		this.m_hThumbRelocator = new ThumbRelocator( ptrInputCode.Handle, hCodeWriter.Handle );
    }
    Reset( ptrInputCode:Pointer, hCodeWriter:CodeWriterThumb ):void {
		this.m_hThumbRelocator.reset( ptrInputCode.Handle, hCodeWriter.Handle );
	}

	// Properties
	IsAtEndOfBlock():boolean { return this.m_hThumbRelocator.eob; } // A Branch of any kind has been reached
	IsAtEndOfInput():boolean { return this.m_hThumbRelocator.eoi; } // Code beyond may not be valid

	// Methods
	Cleanup():void { this.m_hThumbRelocator.dispose(); }

	// Read instructions to internal buffer 
	ReadNext():number { return this.m_hThumbRelocator.readOne(); } // returns number of bytes read so far

	GetLastInstructionRead():CPUInstruction | null {
        if ( this.m_hThumbRelocator.input == null )
            return null;
        return new CPUInstruction( this.m_hThumbRelocator.input as ArmInstruction );
    }

	// Write buffered instructions
	WriteNext():void { this.m_hThumbRelocator.writeOne(); }
	SkipNext():void  { this.m_hThumbRelocator.skipOne(); }
	CopyNext():void  { this.m_hThumbRelocator.copyOne(); } // Doesn't advance output cursor
	
	WriteAll():void { this.m_hThumbRelocator.writeAll(); }

	PeekNextWriteInstr():CPUInstruction | null {
        let tmpInstr:Instruction | null = this.m_hThumbRelocator.peekNextWriteInsn();
        if ( tmpInstr == null )
            return null;
        return new CPUInstruction( tmpInstr as ArmInstruction );
    }
	PeekNextWriteAddress():Pointer { return new Pointer( this.m_hThumbRelocator.peekNextWriteSource() ); }
}


