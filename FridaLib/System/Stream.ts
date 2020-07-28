////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/System/Stream.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Files & Streams IO
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Native/Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    IOFile,

    // Stream,
    IStream,
    OStream
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The IOFile class
class IOFile {
    // Members
	private m_hFile:File;

	// Getter
	get Handle():File { return this.m_hFile; }

	// Constructor
	constructor( hFile:File ) {
		this.m_hFile = hFile;
    }
    static Create( strPath:string, strMode:string ):IOFile {
        return new IOFile( new File(strPath, strMode) );
    }

    // Methods
    Flush():void { this.m_hFile.flush(); }
    Close():void { this.m_hFile.close(); }

    Write( hData:string | ArrayBuffer ):void { this.m_hFile.write(hData); }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The Stream class
// class Stream {
//     // Members
// 	private m_hIOStream:IOStream;

// 	// Getter
// 	get Handle():IOStream { return this.m_hIOStream; }

// 	// Constructor
// 	constructor( hIOStream:IOStream ) {
// 		this.m_hIOStream = hIOStream;
//     }

//     // Properties
//     GetInput():IStream  { return new IStream(this.m_hIOStream.input); }
//     GetOutput():OStream { return new OStream(this.m_hIOStream.output); }

//     // Methods
//     Close():void { this.m_hIOStream.close(); }
// }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The IStream class
class IStream {
    // Members
	private m_hInputStream:InputStream;

	// Getter
    get Handle():InputStream { return this.m_hInputStream; }
    
    // Constructor
	constructor( hInputStream:InputStream ) {
		this.m_hInputStream = hInputStream;
    }
    static CreateWin32( hFileHandle:Pointer, bAutoClose:boolean = true ):IStream {
        return new IStream( new Win32InputStream(hFileHandle.Handle, {autoClose: bAutoClose}) );
    }
    static CreateUNIX( iFileDescriptor:number, bAutoClose:boolean = true ):IStream {
        return new IStream( new UnixInputStream(iFileDescriptor, {autoClose: bAutoClose}) );
    }

    // Methods
    Close():void { this.m_hInputStream.close(); }

    Read( iSize:number ):Promise<ArrayBuffer>    { return this.m_hInputStream.read(iSize); }
    ReadAll( iSize:number ):Promise<ArrayBuffer> { return this.m_hInputStream.readAll(iSize); }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The OStream class
class OStream {
    // Members
	private m_hOutputStream:OutputStream;

	// Getter
    get Handle():OutputStream { return this.m_hOutputStream; }
    
    // Constructor
	constructor( hOutputStream:OutputStream ) {
		this.m_hOutputStream = hOutputStream;
    }
    static CreateWin32( hFileHandle:Pointer, bAutoClose:boolean = true ):OStream {
        return new OStream( new Win32OutputStream(hFileHandle.Handle, {autoClose: bAutoClose}) );
    }
    static CreateUNIX( iFileDescriptor:number, bAutoClose:boolean = true ):OStream {
        return new OStream( new UnixOutputStream(iFileDescriptor, {autoClose: bAutoClose}) );
    }

    // Methods
    Close():void { this.m_hOutputStream.close(); }

    Write( hData:ArrayBuffer | number[] ):Promise<number> { return this.m_hOutputStream.write(hData); }
    WriteAll( hData:ArrayBuffer | number[] ):void         { this.m_hOutputStream.writeAll(hData); }

    WriteMemory( ptrAddress:Pointer, iSize:number ):Promise<number> {
        return this.m_hOutputStream.writeMemoryRegion( ptrAddress.Handle, iSize );
    }
}
