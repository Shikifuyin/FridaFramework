////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Tool Box by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';














////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The FridaToolBox.Log class
FridaToolBox.Log = class {
	// Initialize
	constructor() {}
	
	// Colors
	static Color = {
		White: 0x00ffffff,
		Black: 0x00000000,
		
		Gray: 0x00aaaaaa,
		
		Red:   0x00ff0000,
		Green: 0x0000ff00,
		Blue:  0x000000ff,
		
		Cyan:    0x00ffff00,
		Magenta: 0x00ff00ff,
		Yellow:  0x0000ffff,
		
		LightGray: 0x00cccccc,
		
		LightRed:   0x007f0000,
		LightGreen: 0x00007f00,
		LightBlue:  0x0000007f,
		
		LightCyan:    0x007f7f00,
		LightMagenta: 0x007f007f,
		LightYellow:  0x00007f7f
	};
	
	// Main Logger
	static Message( hInput, strLogLevel, iFrontColorRGB = null, iBackColorRGB = null )
	{
		// Transform to a pretty string
		var strMessage = "";
		if ( typeof hInput === 'object' )
			strMessage = JSON.stringify( hInput, null, 2 );
		else
			strMessage = hInput.toString();
		
		// Apply coloring
		if ( iFrontColorRGB != null ) {
			var strColorCode = "\x1b[38;2;" + ((iFrontColorRGB >> 16) & 0xff) + ";" + ((iFrontColorRGB >> 8) & 0xff) + ";" + (iFrontColorRGB & 0xff) + "m";
			strMessage = strColorCode + strMessage;
		}
		if ( iBackColorRGB != null ) {
			var strColorCode = "\x1b[48;2;" + ((iBackColorRGB >> 16) & 0xff) + ";" + ((iBackColorRGB >> 8) & 0xff) + ";" + (iBackColorRGB & 0xff) + "m";
			strMessage = strColorCode + strMessage;
		}
		
		var strReset = "\x1b[0m";
		if ( iFrontColorRGB != null || iBackColorRGB != null ) {
			strMessage = strMessage + strReset;
		}
		
		// Done
		console[strLogLevel]( strMessage );
	}
	
	// Wrappers
	static Info( hInput, iFrontColorRGB = null ) {
		FridaToolBox.Log.Message( hInput, "log", iFrontColorRGB, Color.Black );
	}
	static Warning( hInput, iFrontColorRGB = Color.Yellow ) {
		FridaToolBox.Log.Message( hInput, "warn", iFrontColorRGB, Color.Black );
	}
	static Error( hInput, iFrontColorRGB = Color.Red ) {
		FridaToolBox.Log.Message( hInput, "error", iFrontColorRGB, Color.Black );
	}
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The FridaToolBox.Trace class
FridaToolBox.Trace = class {
	// Initialize
	constructor() {}
	
	
	
	// Exception-based backtrace
	static FromException() {
		var strResult = "";
		
		Java.perform( function() {
			var hLog = Java.use( "android.util.Log" );
			var hException = Java.use( "java.lang.Exception" );
			strResult = hLog.getStackTraceString(hException.$new());
		});
		
		return strResult;
	}
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The FridaToolBox.Enumerate class
FridaToolBox.Enumerate = class {
	// Initialize
	constructor() {}
	
	// Classes
	static EnumClasses( strPattern )
	{
		var iMatchCount = 0;
		
		// Say Hello
		FridaToolBox.Log.Info( "[EnumClasses] Starting enumeration (pattern='" + strPattern + "') ..." );
		
		// Enumerate all loaded classes
		Java.enumerateLoadedClasses({
			
			onMatch: function( strClassName ) {
				// Filter out
				var bMatched = strClassName.includes( strPattern );
				if ( !bMatched ) {
					return;
				}
				
				FridaToolBox.Log.Info( "[EnumClasses] Found matching class : " + strClassName, Color.LightGreen );
				
				// Count
				++iMatchCount;
			},
			
			onComplete: function() {
				FridaToolBox.Log.Info( "[EnumClasses] Done, found " + iMatchCount + " matching classes !" );
			}
			
		});
	}
	
	// Instances
	static EnumInstances( strClassName )
	{
		var iMatchCount = 0;
		
		// Say Hello
		FridaToolBox.Log.Info( "[EnumInstances] Starting enumeration (class='" + strClassName + "') ..." );
		
		// Scan Memory for instances
		Java.choose( strClassName, {
			
			onMatch: function( hInstance ) {
				FridaToolBox.Log.Info( "[EnumInstances] Found instance at address : " + hInstance, Color.LightGreen );
				FridaToolBox.Log.Info( "[EnumInstances] -> Object Content :", Color.LightBlue );
				FridaToolBox.Log.Info( hInstance, Color.LightBlue );
				
				// Count
				++iMatchCount;
			},
			
			onComplete: function() {
				FridaToolBox.Log.Info( "[EnumInstances] Done, found " + iMatchCount + " matching instances !" );
			}
			
		});
	}
	
	// Native Methods
	static EnumNativeMethods()
	{
		// Say Hello
		FridaToolBox.Log.Info( "[EnumNativeMethods] Starting enumeration ..." );
	
		// Get pointer size
		var iPointerSize = FridaToolBox.GetPointerSize();
		
		// See https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
		var iFindClassIndex = 6;         // jclass FindClass(JNIEnv *env, const char *name);
		var iRegisterNativesIndex = 215; // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
		
		// Environment allows to recover native addresses
		var hEnv = Java.vm.getEnv();
		function GetNativeAddress( iIndex ) {
			return hEnv.handle.readPointer().add(iIndex * iPointerSize).readPointer();
		}
		
		// Intercept FindClass calls to populate our map
		var mapAddressToName = {};
		Interceptor.attach( GetNativeAddress(iFindClassIndex), {
			
			onEnter: function( args ) {
				// args[0] -> JNIEnv * env
				// args[1] -> const char * name
				var strName = args[1].readCString();
				
				// this -> jclass name
				FridaToolBox.Log.Info( "[EnumNativeMethods] Intercepted jclass : " + strName, Color.LightGreen );
				mapAddressToName[args[0]] = strName;
			}
			
		});
		
		// Intercept RegisterNatives calls
		Interceptor.attach( GetNativeAddress(iRegisterNativesIndex), {
			
			onEnter: function( args ) {
				// args[0] -> JNIEnv * env
				// args[1] -> jclass clazz
				// args[2] -> const JNINativeMethod * methods
				// args[3] -> jint nMethods
				var strJClassName = mapAddressToName[args[0]];
				var pMethods = ptr( args[2] );
				var iMethodCount = parseInt( args[3] );
				
				// JNINativeMethod struct
				//typedef struct {
				//	const char * name;
				//	const char * signature;
				//	void * fnPtr;
				//} JNINativeMethod;
				var iStructSize = 3 * iPointerSize; // sizeof(JNINativeMethod)
				var iNameOffset      = 0;
				var iSignatureOffset = iPointerSize;
				var iFnPtrOffset     = 2 * iPointerSize;
				
				// Parse jclass name
				var arrJClassNameElements = strJClassName.split('/');
				var strPackageName = arrJClassNameElements.slice(0,-1).join('.');
				var strClassName = arrJClassNameElements[arrJClassNameElements.length - 1];
				
				// Enum all methods
				for( var i = 0; i < iMethodCount; ++i ) {
					var iMethodOffset = i * iStructSize;
					var strName      = pMethods.add( iMethodOffset + iNameOffset ).readPointer().readCString();
					var strSignature = pMethods.add( iMethodOffset + iSignatureOffset ).readPointer().readCString();
					var pFnPtr       = pMethods.add( iMethodOffset + iFnPtrOffset ).readPointer();
					
					FridaToolBox.Log.Info( "[EnumNativeMethods] Intercepted method :", Color.LightGreen );
					FridaToolBox.Log.Info(
						{
							module: DebugSymbol.fromAddress(pFnPtr)['moduleName'],
							package: strPackageName,
							class: strClassName,
							method: strName,
							signature: strSignature, // Signature parser (JADX) : https://github.com/skylot/jadx/blob/master/jadx-core/src/main/java/jadx/core/dex/nodes/parser/SignatureParser.java
							address: pFnPtr
						},
						Color.LightBlue
					);
				}
			}
			
		});
	}
	
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The FridaToolBox.Hook class
FridaToolBox.Hook = class {
	// Initialize
	constructor() {}
	
	// Methods, Options :
	// -- 'method'       = (String) Method name, default = '$init'
	// -- 'arguments'    = (Array of String) Argument types list, default = []
	// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
	// -- 'callOriginal' = (Boolean) Whether to call the original method, default = true
	// -- 'argcallback'  = (function) Callback before original call, default = null
	//                     Prototype = arrNewArgs function(strClassName, strMethodName, arrOriginalArgs, self);
	// -- 'retcallback'  = (function) Callback after original call, default = null
	//                     Prototype = hNewRetValue function(strClassName, strMethodName, arrEffectiveArgs, hOriginalRetValue, self);
	static HookMethod( strClassName, arrOptions )
	{
		// Parse options
		var strMethodName   = ( arrOptions['method'] !== undefined )       ? arrOptions['method'] : '$init';
		var arrArguments    = ( arrOptions['arguments'] !== undefined )    ? arrOptions['arguments'] : [];
		var bStackTrace     = ( arrOptions['stacktrace'] !== undefined )   ? arrOptions['stacktrace'] : false;
		var bCallOriginal   = ( arrOptions['callOriginal'] !== undefined ) ? arrOptions['callOriginal'] : true;
		var funcArgCallback = ( arrOptions['argcallback'] !== undefined )  ? arrOptions['argcallback'] : null;
		var funcRetCallback = ( arrOptions['retcallback'] !== undefined )  ? arrOptions['retcallback'] : null;
		
		// Say Hello
		FridaToolBox.Log.Info( "[HookMethod:INFO] Hooked " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrArguments) + ")" );
		
		// Get class handle
		var hClass = Java.use( strClassName );
		
		// Get overloaded method
		var hMethod = hClass[strMethodName].overload.apply( null, arrArguments );
		
		// Replace implementation
		hMethod.implementation = function() {
			// Retrieve original arguments as an array
			var arrOriginalArgs = [].slice.call( arguments );
			
			// Call start
			FridaToolBox.Log.Info( "[HookMethod:INFO] Call Start : " + strClassName + "." + strMethodName + "(" + JSON.stringify(arrOriginalArgs) + ")", Color.Green );
			
			// Log stack trace
			if ( bStackTrace ) {
				FridaToolBox.Log.Info( "[HookMethod:INFO] ------- STACK TRACE BEGIN -------", Color.Blue );
				FridaToolBox.Trace.FromThread( this );
				FridaToolBox.Log.Info( "[HookMethod:INFO] -------- STACK TRACE END --------", Color.Blue );
			}
			
			// Raise callback
			var arrEffectiveArgs = null;
			if ( funcArgCallback != null ) {
				FridaToolBox.Log.Info( "[HookMethod:INFO] Raising arguments callback ...", Color.Blue );
				arrEffectiveArgs = funcArgCallback( strClassName, strMethodName, arrOriginalArgs );
			}
			
			// Call original function
			var hOriginalRetVal = null;
			if ( bCallOriginal ) {
				FridaToolBox.Log.Info( "[HookMethod:INFO] Calling original method ...", Color.Blue );
				hOriginalRetVal = this[strMethodName].apply( this, arrOriginalArgs, self );
				FridaToolBox.Log.Info( "[HookMethod:INFO] Original method returned : " + JSON.stringify(hResult), Color.Blue );
			}
			
			// Raise callback
			var hEffectiveRetVal = null;
			if ( funcRetCallback != null ) {
				FridaToolBox.Log.Info( "[HookMethod:INFO] Raising retval callback ...", Color.Blue );
				hEffectiveRetVal = funcRetCallback( strClassName, strMethodName, arrEffectiveArgs, hOriginalRetVal );
			}
			
			// Call end
			FridaToolBox.Log.Info( "[HookMethod:INFO] Call End, returning : " + JSON.stringify(hEffectiveRetVal), Color.Blue );
			
			// Done
			return hEffectiveRetVal;
		};
	}
	
	// Classes, Options :
	// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
	// -- 'callOriginal' = (Boolean) Whether to call the original method, default = true
	// -- 'argcallback'  = (function) Callback before original call, default = null
	//                     Prototype = arrNewArgs function(strClassName, strMethodName, arrOriginalArgs, self);
	// -- 'retcallback'  = (function) Callback after original call, default = null
	//                     Prototype = hNewRetValue function(strClassName, strMethodName, arrEffectiveArgs, hOriginalRetValue, self);
	static HookClass( strClassName, arrOptions )
	{
		// Say Hello
		FridaToolBox.Log.Info( "[HookClass:INFO] Hooking all methods from " + strClassName );
		
		// Get class handle
		var hClass = Java.use( strClassName );
		
		// Get all methods
		var arrMethods = hClass.class.getDeclaredMethods();
		hClass.$dispose();
		
		// Hook all methods
		arrMethods.forEach( function(hMethod) {
			// Get Method name
			var strMethodName = hMethod.getName();
			
			// Get Parameter Types names
			var arrParameterTypes = hMethod.getParameterTypes();
			var arrParameterTypeNames = [];
			arrParameterTypes.forEach( function(hParam) {
				arrParameterTypeNames.push( hParam.getName() );
			});
			
			// Build Options
			arrHookMethodOptions = {
				method: strMethodName,
				arguments: arrParameterTypeNames,
				stacktrace: arrOptions['stacktrace'],
				callOriginal: arrOptions['callOriginal'],
				argcallback: arrOptions['argcallback'],
				retcallback: arrOptions['retcallback']
			};
			
			// Hook Method
			FridaToolBox.Hook.HookMethod( strClassName, arrHookMethodOptions );
		});
	}
	
	// Native Methods (JNI), Options :
	// -- 'stacktrace'   = (Boolean) Whether to show stack trace for the call, default = false
	// -- 'argcallback'  = (function) Callback before original call, default = null
	//                     Prototype = function( arrArgs );
	// -- 'retcallback'  = (function) Callback after original call, default = null
	//                     Prototype = function( retValue );
	// Obtaining address : $ nm --demangle --dynamic somelib.so | grep "SomeClass::SomeMethod("
	static HookNativeMethod( strModuleName, iNativeMethodAddress, arrOptions )
	{
		// Parse options
		var bStackTrace     = ( arrOptions['stacktrace'] !== undefined )  ? arrOptions['stacktrace'] : false;
		var funcArgCallback = ( arrOptions['argcallback'] !== undefined ) ? arrOptions['argcallback'] : null;
		var funcRetCallback = ( arrOptions['retcallback'] !== undefined ) ? arrOptions['retcallback'] : null;
		
		// Say Hello
		FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Hooked " + strModuleName + " - " + iNativeMethodAddress );
		
		// Intercept dlopen calls
		Interceptor.attach( Module.findExportByName(null, "dlopen"), {
			
			onEnter: function( dlopen_args ) {
				// Get library name
				this.libraryName = Memory.readUtf8String( dlopen_args[0] );
				FridaToolBox.Log.Info( "[HookNativeMethod:INFO] dlopen called for library : " + this.libraryName, Color.Green );
			},
			
			onLeave: function( dlopen_retval ) {
				// Filter module name
				var bMatch = this.libraryName.endsWith( strModuleName );
				if ( !bMatch )
					return;
				
				// Found a match
				FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Matched module name ! dlopen returned " + dlopen_retval, Color.Green );
				
				// Intercept Native method
				var iBaseAddress = Module.findBaseAddress( strModuleName );
				Interceptor.attach( iBaseAddress.add(iNativeMethodAddress), {
					
					onEnter: function( args ) {
						FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Call Start ...", Color.Green );
						
						// Log stack trace
						if ( bStackTrace ) {
							FridaToolBox.Log.Info( "[HookNativeMethod:INFO] ------- STACK TRACE BEGIN -------", Color.Blue );
							FridaToolBox.Trace.FromThread( this );
							FridaToolBox.Log.Info( "[HookNativeMethod:INFO] -------- STACK TRACE END --------", Color.Blue );
						}
						
						// Raise callback
						if ( funcArgCallback != null ) {
							FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Raising arguments callback ...", Color.Blue );
							funcArgCallback( args );
						}
					},
					
					onLeave: function( retval ) {
						// Raise callback
						if ( funcRetCallback != null ) {
							FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Raising retval callback ...", Color.Blue );
							funcRetCallback( retval );
						}
						
						FridaToolBox.Log.Info( "[HookNativeMethod:INFO] Call End ...", Color.Blue );
					}
					
				});
			}
			
		});
	}
	
};



