////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/System/Log.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Logging stuff
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { Pointer } from "../Native/Pointer";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    HexDumpOptions,

    LogLevel,
    LogIntput,
    Color,

    HexDump,

    Message,
    Info,
    Warning,
    Error,
    Clear,
    IndentAdd,
    IndentEnd,

    Assert,

    Count,
    CountReset,

    TimerStart,
    TimerEnd,
    TimerLog
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log Interfaces : Hex Dump
interface HexDumpOptions {
    Offset?:number;      // Default = 0
    Size?:number;
    Header?:boolean;     // Default = true
    ANSIColors?:boolean; // Default = false
}

function _ConvertFrom_HexDumpOptions( hHexDumpOptions:HexDumpOptions ):HexdumpOptions {
    let hConverted:HexdumpOptions = {};
    hConverted.offset = hHexDumpOptions.Offset;
    hConverted.length = hHexDumpOptions.Size;
    hConverted.header = hHexDumpOptions.Header;
    hConverted.ansi = hHexDumpOptions.ANSIColors;

    return hConverted;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log Interfaces : Pretty Messages
const enum LogLevel {
    Info = 'log',
    Warning = 'warn',
    Error = 'error'
};

type LogIntput = string | Pointer | ArrayBuffer | Object;

const enum Color {
    White = 0x00ffffff,
    Black = 0x00000000,
    
    Gray = 0x00aaaaaa,
    
    Red   = 0x00ff0000,
    Green = 0x0000ff00,
    Blue  = 0x000000ff,
    
    Cyan    = 0x00ffff00,
    Magenta = 0x00ff00ff,
    Yellow  = 0x0000ffff,
    
    LightGray = 0x00cccccc,
    
    LightRed   = 0x007f0000,
    LightGreen = 0x00007f00,
    LightBlue  = 0x0000007f,
    
    LightCyan    = 0x007f7f00,
    LightMagenta = 0x007f007f,
    LightYellow  = 0x00007f7f
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log : Hex Dump
function HexDump( hInput:ArrayBuffer | Pointer, hOptions:HexDumpOptions | undefined = undefined ):string {
    let hOpt:HexdumpOptions | undefined = undefined;
    if ( hOptions != undefined )
        hOpt = _ConvertFrom_HexDumpOptions( hOptions );

    if ( hInput instanceof Pointer )
        return hexdump( hInput.Handle, hOpt );
    return hexdump( hInput, hOpt );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log : Pretty Messages
function Message( hInput:LogIntput, strLogLevel:LogLevel, iFrontColorRGB:number | undefined = undefined, iBackColorRGB:number | undefined = undefined ):void {
    // Transform to a pretty string
    let strMessage:string = "";
    if ( hInput instanceof ArrayBuffer || hInput instanceof Pointer )
        strMessage = HexDump( hInput );
    else if ( typeof hInput === 'object' )
        strMessage = JSON.stringify( hInput, null, 2 );
    else
        strMessage = hInput;
    
    // Apply coloring
    if ( iFrontColorRGB != null ) {
        let strColorCode:string = "\x1b[38;2;" + ((iFrontColorRGB >> 16) & 0xff) + ";" + ((iFrontColorRGB >> 8) & 0xff) + ";" + (iFrontColorRGB & 0xff) + "m";
        strMessage = strColorCode + strMessage;
    }
    if ( iBackColorRGB != null ) {
        let strColorCode:string = "\x1b[48;2;" + ((iBackColorRGB >> 16) & 0xff) + ";" + ((iBackColorRGB >> 8) & 0xff) + ";" + (iBackColorRGB & 0xff) + "m";
        strMessage = strColorCode + strMessage;
    }
    
    let strReset:string = "\x1b[0m";
    if ( iFrontColorRGB != null || iBackColorRGB != null ) {
        strMessage = strMessage + strReset;
    }
    
    // Done
    switch( strLogLevel ) {
        case LogLevel.Info:    console.info( strMessage ); break;
        case LogLevel.Warning: console.warn( strMessage ); break;
        case LogLevel.Error:   console.error( strMessage ); break;
    }
}

function Info( hInput:LogIntput, iFrontColorRGB:number | undefined = undefined ) {
    Message( hInput, LogLevel.Info, iFrontColorRGB, Color.Black );
}
function Warning( hInput:LogIntput, iFrontColorRGB = Color.Yellow ) {
    Message( hInput, LogLevel.Warning, iFrontColorRGB, Color.Black );
}
function Error( hInput:LogIntput, iFrontColorRGB = Color.Red ) {
    Message( hInput, LogLevel.Error, iFrontColorRGB, Color.Black );
}

function Clear():void {
    console.clear();
}

function IndentAdd( strLabel:string | undefined ):void {
    console.group( strLabel );
}
function IndentEnd():void {
    console.groupEnd();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log : Assertions
function Assert( mValue:any, strMessage:string | undefined = undefined ):void {
    console.assert( mValue, strMessage );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log : Counters
function Count( strLabel:string ):void {
    console.count( strLabel );
}
function CountReset( strLabel:string ):void {
    console.countReset( strLabel );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log : Timers
function TimerStart( strLabel:string ):void {
    console.time( strLabel );
}
function TimerEnd( strLabel:string ):void {
    console.timeEnd( strLabel );
}

function TimerLog( strLabel:string ):void {
    console.timeLog( strLabel );
}

