////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/FridaLib.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Frida Library master module
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO : Missing Objective-C stuff ... Don't care about MacOS/iOS for now !
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import * as Native from "./Native/Native";
import * as Memory from "./Memory/Memory";
import * as Env from "./Environment/Environment";

import * as Process from "./System/Process";
import * as Thread from "./System/Thread";
import * as Module from "./System/Module";
import * as Kernel from "./System/Kernel";

import * as Java from "./Instrument/Java";
import * as Interceptor from "./Instrument/Interceptor";
import * as Stalker from "./Instrument/Stalker";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    Native,
    Memory,
    Env,

    Process,
    Thread,
    Module,
    Kernel,

    Java,
    Interceptor,
    Stalker
};

