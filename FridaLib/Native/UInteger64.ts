////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/Native/UInteger64.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Native UInt64 type
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    UInteger64
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UInteger64 Type Casts
function _TypeCast( mValue:number | string | UInteger64 | UInt64 ):number | string | UInt64 {
	return ( mValue instanceof UInteger64 ) ? (mValue as UInteger64).Handle : mValue;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The UInteger64 class
class UInteger64
{
	// Members
	private m_hUInt64:UInt64;

	// Getter
	get Handle():UInt64 { return this.m_hUInt64; }

	// Constructor
	constructor( mValue:number | string | UInteger64 | UInt64 ) {
		if ( mValue instanceof UInt64 )
			this.m_hUInt64 = mValue;
		else
			this.m_hUInt64 = new UInt64( _TypeCast(mValue) );
	}
	Reset( mValue:number | string | UInteger64 ):void {
		this.m_hUInt64 = new UInt64( _TypeCast(mValue) );
	}

	// Convert
	toNumber():number                     { return this.m_hUInt64.toNumber(); }
	toString( iRadix:number = 10 ):string { return this.m_hUInt64.toString(iRadix); }

	// Compare
	Equals( mValue:number | string | UInteger64 ):boolean {
		return this.m_hUInt64.equals( _TypeCast(mValue) );
	}
	Cmp( mValue:number | string | UInteger64 ):number {
		return this.m_hUInt64.compare( _TypeCast(mValue) );
	}

	// Arithmetics
	Add( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.add( _TypeCast(mValue) ) );
	}
	Sub( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.sub( _TypeCast(mValue) ) );
	}

	// Bitwise
	Not():UInteger64 {
		return new UInteger64( this.m_hUInt64.not() );
	}
	And( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.and( _TypeCast(mValue) ) );
	}
	Or( mValue:number | string | UInteger64 ):UInteger64  {
		return new UInteger64( this.m_hUInt64.or( _TypeCast(mValue) ) );
	}
	Xor( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.xor( _TypeCast(mValue) ) );
	}

	ShL( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.shl( _TypeCast(mValue) ) );
	}
	ShR( mValue:number | string | UInteger64 ):UInteger64 {
		return new UInteger64( this.m_hUInt64.shr( _TypeCast(mValue) ) );
	}
}

