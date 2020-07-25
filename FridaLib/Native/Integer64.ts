////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/Integer64.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Native Int64 type
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    Integer64
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Integer64 Type Casts
function _TypeCast( mValue:number | string | Integer64 | Int64 ):number | string | Int64 {
	return ( mValue instanceof Integer64 ) ? (mValue as Integer64).Handle : mValue;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The Integer64 class
class Integer64
{
	// Members
	private m_hInt64:Int64;

	// Getter
	get Handle():Int64 { return this.m_hInt64; }

	// Constructor
	constructor( mValue:number | string | Integer64 | Int64 ) {
		if ( mValue instanceof Int64 )
			this.m_hInt64 = mValue;
		else
			this.m_hInt64 = new Int64( _TypeCast(mValue) );
	}
	Reset( mValue:number | string | Integer64 ):void {
		this.m_hInt64 = new Int64( _TypeCast(mValue) );
	}

	// Convert
	toNumber():number                     { return this.m_hInt64.toNumber(); }
	toString( iRadix:number = 10 ):string { return this.m_hInt64.toString(iRadix); }

	// Compare
	Equals( mValue:number | string | Integer64 ):boolean {
		return this.m_hInt64.equals( _TypeCast(mValue) );
	}
	Cmp( mValue:number | string | Integer64 ):number {
		return this.m_hInt64.compare( _TypeCast(mValue) );
	}

	// Arithmetics
	Add( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.add( _TypeCast(mValue) ) );
	}
	Sub( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.sub( _TypeCast(mValue) ) );
	}

	// Bitwise
	Not():Integer64 {
		return new Integer64( this.m_hInt64.not() );
	}
	And( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.and( _TypeCast(mValue) ) );
	}
	Or( mValue:number | string | Integer64 ):Integer64  {
		return new Integer64( this.m_hInt64.or( _TypeCast(mValue) ) );
	}
	Xor( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.xor( _TypeCast(mValue) ) );
	}

	ShL( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.shl( _TypeCast(mValue) ) );
	}
	ShR( mValue:number | string | Integer64 ):Integer64 {
		return new Integer64( this.m_hInt64.shr( _TypeCast(mValue) ) );
	}
}

