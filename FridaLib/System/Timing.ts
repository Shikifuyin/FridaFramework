////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/System/Timing.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Timing Events
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    TimingCallback,

    SetTimeout,
    ClearTimeout,
    SetInterval,
    ClearInterval,
    SetImmediate,
    ClearImmediate
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Timing Interfaces
interface TimingCallback {
    ( arrParams:any[] ):void
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Timing Functions
function SetTimeout( funcCallback:TimingCallback, iDelayMS:number, ...arrParams:any[] ):NodeJS.Timeout {
    return setTimeout( funcCallback, iDelayMS, arrParams );
}
function ClearTimeout( hIdentifier:NodeJS.Timeout ):void {
    clearTimeout( hIdentifier );
}

function SetInterval( funcCallback:TimingCallback, iDelayMS:number, ...arrParams:any[] ):NodeJS.Timeout {
    return setInterval( funcCallback, iDelayMS, arrParams );
}
function ClearInterval( hIdentifier:NodeJS.Timeout ):void {
    clearInterval( hIdentifier );
}

function SetImmediate( funcCallback:TimingCallback, ...arrParams:any[] ):NodeJS.Immediate {
    return setImmediate( funcCallback, arrParams );
}
function ClearImmediate( hIdentifier:NodeJS.Immediate ):void {
    clearImmediate( hIdentifier );
}
