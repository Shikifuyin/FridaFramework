////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/Pointer.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Native Pointer type
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { assert } from "console";

import { Integer64 } from "./Integer64"
import { UInteger64 } from "./UInteger64"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    StringEncoding,
    
    PointerSignKey,

    Pointer
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Pointer Interfaces : String Encoding
const enum StringEncoding {
    ASCII = 1, // "C" strings
    UTF8,
    UTF16,
    ANSI       // Windows only
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Pointer Interfaces : Pointer Authentication
const enum PointerSignKey {
	IA = 'ia', // Code pointers, default
	IB = 'ib', // Code pointers
	DA = 'da', // Data pointers
	DB = 'db'  // Data pointers
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Pointer Type Casts
function _TypeCast( mValue:number | string | Integer64 | UInteger64 | Pointer | NativePointer ):number | string | Int64 | UInt64 | NativePointer {
    if ( mValue instanceof Integer64 || mValue instanceof UInteger64 || mValue instanceof Pointer )
        return mValue.Handle;
    return mValue;
}

function _TypeCastInt64( mValue:number | Integer64 ):number | Int64 {
    return ( mValue instanceof Integer64 ) ? mValue.Handle : mValue;
}
function _TypeCastUInt64( mValue:number | UInteger64 ):number | UInt64 {
    return ( mValue instanceof UInteger64 ) ? mValue.Handle : mValue;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The Pointer class
class Pointer
{
    // Members
    protected m_hNativePointer:NativePointer;

	// Getter
	get Handle():NativePointer { return this.m_hNativePointer; }

    // Constructor
    constructor( mValue:number | string | Integer64 | UInteger64 | Pointer | NativePointer ) {
		if ( mValue instanceof NativePointer )
			this.m_hNativePointer = mValue;
		else
			this.m_hNativePointer = new NativePointer( _TypeCast(mValue) );
	}
	Reset( mValue:number | string | Integer64 | UInteger64 | Pointer ):void {
		this.m_hNativePointer = new NativePointer( _TypeCast(mValue) );
    }

    // NULL Pointer
    static NULL:Pointer = new Pointer(0);
	IsNull():boolean { return this.m_hNativePointer.isNull(); }

    // Convert
    toInt32():number                      { return this.m_hNativePointer.toInt32(); }
	toString( iRadix:number = 16 ):string { return this.m_hNativePointer.toString(iRadix); }
	toScanPattern():string                { return this.m_hNativePointer.toMatchPattern(); } // For use in Memory Scanner

    // Compare
	Equals( mValue:number | string | Integer64 | UInteger64 | Pointer ):boolean {
		return this.m_hNativePointer.equals( _TypeCast(mValue) );
	}
	Cmp( mValue:number | string | Integer64 | UInteger64 | Pointer ):number {
		return this.m_hNativePointer.compare( _TypeCast(mValue) );
    }
    
	// Arithmetics
	Add( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.add( _TypeCast(mValue) ) );
	}
	Sub( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.sub( _TypeCast(mValue) ) );
	}

	// Bitwise
	Not():Pointer {
		return new Pointer( this.m_hNativePointer.not() );
	}
	And( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.and( _TypeCast(mValue) ) );
	}
	Or( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer  {
		return new Pointer( this.m_hNativePointer.or( _TypeCast(mValue) ) );
	}
	Xor( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.xor( _TypeCast(mValue) ) );
	}

	ShL( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.shl( _TypeCast(mValue) ) );
	}
	ShR( mValue:number | string | Integer64 | UInteger64 | Pointer ):Pointer {
		return new Pointer( this.m_hNativePointer.shr( _TypeCast(mValue) ) );
	}

	// Dereferencing : Read value
	ReadPointer():Pointer { return new Pointer( this.m_hNativePointer.readPointer() ); }

	ReadInt8():number  { return this.m_hNativePointer.readS8(); }
	ReadInt16():number { return this.m_hNativePointer.readS16(); }
	ReadInt32():number { return this.m_hNativePointer.readS32(); }
	ReadShort():number { return this.m_hNativePointer.readShort(); }
	ReadInt():number   { return this.m_hNativePointer.readInt(); }

    ReadInt64():Integer64   { return new Integer64( this.m_hNativePointer.readS64() ); }
    ReadLong():Integer64 | number {
        let iValue:Int64 | number = this.m_hNativePointer.readLong();
        return ( iValue instanceof Int64 ) ? new Integer64(iValue) : iValue;
    }

	ReadUInt8():number  { return this.m_hNativePointer.readU8(); }
	ReadUInt16():number { return this.m_hNativePointer.readU16(); }
	ReadUInt32():number { return this.m_hNativePointer.readU32(); }
	ReadUShort():number { return this.m_hNativePointer.readUShort(); }
	ReadUInt():number   { return this.m_hNativePointer.readUInt(); }

    ReadUInt64():UInteger64 { return new UInteger64( this.m_hNativePointer.readU64() ); }
	ReadULong():UInteger64 | number  {
        let iValue:UInt64 | number = this.m_hNativePointer.readULong();
        return ( iValue instanceof UInt64 ) ? new UInteger64(iValue) : iValue;
    }

    ReadFloat():number  { return this.m_hNativePointer.readFloat(); }
    ReadDouble():number { return this.m_hNativePointer.readDouble(); }
    
	ReadString( iType:StringEncoding, iLength:number | undefined = undefined ):string | null {
		switch( iType ) {
			case StringEncoding.ASCII: return this.m_hNativePointer.readCString( iLength );
			case StringEncoding.UTF8:  return this.m_hNativePointer.readUtf8String( iLength );
			case StringEncoding.UTF16: return this.m_hNativePointer.readUtf16String( iLength );
			case StringEncoding.ANSI:  return this.m_hNativePointer.readAnsiString( iLength );
			default: assert(false); return null; // Should never happen
        }
    }
    
	ReadByteArray( iSize:number ):ArrayBuffer | null { return this.m_hNativePointer.readByteArray(iSize); }

	// Dereferencing : Write value
	WritePointer( ptrValue:Pointer ):Pointer {
        this.m_hNativePointer.writePointer( ptrValue.m_hNativePointer );
        return this;
    }

	WriteInt8( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeS8( _TypeCastInt64(iValue) );
        return this;
    }
    WriteInt16( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeS16( _TypeCastInt64(iValue) );
        return this;
    }
    WriteInt32( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeS32( _TypeCastInt64(iValue) );
        return this;
    }
    WriteShort( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeShort( _TypeCastInt64(iValue) );
        return this;
    }
    WriteInt( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeInt( _TypeCastInt64(iValue) );
        return this;
    }

    WriteInt64( iValue:number | Integer64 ):Pointer {
        this.m_hNativePointer.writeS64( _TypeCastInt64(iValue) );
        return this;
    }
    WriteLong( iValue:number | Integer64 ):Pointer  {
        this.m_hNativePointer.writeLong( _TypeCastInt64(iValue) );
        return this;
    }

    WriteUInt8( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeU8( _TypeCastUInt64(iValue) );
        return this;
    }
    WriteUInt16( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeU16( _TypeCastUInt64(iValue) );
        return this;
    }
    WriteUInt32( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeU32( _TypeCastUInt64(iValue) );
        return this;
    }
    WriteUShort( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeUShort( _TypeCastUInt64(iValue) );
        return this;
    }
    WriteUInt( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeUInt( _TypeCastUInt64(iValue) );
        return this;
    }

    WriteUInt64( iValue:number | UInteger64 ):Pointer {
        this.m_hNativePointer.writeU64( _TypeCastUInt64(iValue) );
        return this;
    }
	WriteULong( iValue:number | UInteger64 ):Pointer  {
        this.m_hNativePointer.writeULong( _TypeCastUInt64(iValue) );
        return this;
    }

    WriteFloat( fValue:number ):Pointer  {
        this.m_hNativePointer.writeFloat( fValue );
        return this;
    }
    WriteDouble( fValue:number ):Pointer {
        this.m_hNativePointer.writeDouble( fValue );
        return this;
    }

	WriteString( iType:StringEncoding, strValue:string ):Pointer {
		switch( iType ) {
			case StringEncoding.UTF8:  this.m_hNativePointer.writeUtf8String( strValue ); break;
			case StringEncoding.UTF16: this.m_hNativePointer.writeUtf16String( strValue ); break;
			case StringEncoding.ANSI:  this.m_hNativePointer.writeAnsiString( strValue ); break;
			case StringEncoding.ASCII:
			default: assert(false); break; // Should never happen
        }
        return this;
	}
	
	WriteByteArray( arrBytes:number[] | ArrayBuffer ):Pointer {
        this.m_hNativePointer.writeByteArray( arrBytes );
        return this;
    }

	// Memory wrapping
		// Wraps the memory region in an ArrayBuffer.
		// No validation, bad pointer will crash the process !
	WrapMemory( iSize:number ):ArrayBuffer { return ArrayBuffer.wrap( this.m_hNativePointer, iSize ); }
		// Retrieve an ArrayBuffer's base address.
		// Caller is responsible for keeping the ArrayBuffer alive while the returned pointer is being used !
	static Unwrap( arrBytes:ArrayBuffer ):Pointer { return new Pointer( arrBytes.unwrap() ); }

	// Pointer authentication bits for signed code
	Sign( strKey:PointerSignKey = PointerSignKey.IA, iData:number | string | Integer64 | UInteger64 | Pointer = 0 ):Pointer {
        return new Pointer( this.m_hNativePointer.sign( strKey, _TypeCast(iData) ) );
    }
	Unsign( strKey:PointerSignKey = PointerSignKey.IA ):Pointer {
        return new Pointer( this.m_hNativePointer.strip( strKey ) );
    }
	MakeSignData( iSmallInt:number ):Pointer {
        return new Pointer( this.m_hNativePointer.blend( iSmallInt ) );
    }
}

