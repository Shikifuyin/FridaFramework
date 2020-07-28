////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Frida Framework by Shikifuyin
// Version : 1.0
// Requirements : V8 engine, latest version (8.4+), ECMAScript ES2020+ compliance
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// File : ./FridaLib/System/Network.ts
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description : Sockets for Networking
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
'use strict';

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Imports
import { IStream, OStream } from "./Stream";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Exports
export {
    SocketType,
    SocketFamily,
    SocketUNIXType,
    NetAddress,
    UnixAddress,

    ConnectOptionsTCP,
    ConnectOptionsUNIX,
    ConnectOptions,

    ListenOptionsTCP,
    ListenOptionsUNIX,
    ListenOptions,

    Socket
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket Interfaces
enum SocketType {
    TCP   = 'tcp',
    UDP   = 'udp',
    TCPv6 = 'tcp6',
    UDPv6 = 'udp6',
    UnixStream   = 'unix:stream',
    UnixDatagram = 'unix:dgram'
};

enum SocketFamily {
    IPv4 = 'ipv4',
    IPv6 = 'ipv6',
    UNIX = 'unix'
};

enum SocketUNIXType {
    Anonymous      = 'anonymous',
    Path           = 'path',
    Abstract       = 'abstract',
    AbstractPadded = 'abstract-padded'
};

interface IPAddress {
    IP:string;
    Port:number;
}
interface UnixAddress {
    Path:string;
}

type NetAddress = IPAddress | UnixAddress;

function _ConvertTo_NetAddress( hSocketEndpointAddress:SocketEndpointAddress ):NetAddress {
    if ( (hSocketEndpointAddress as TcpEndpointAddress).ip != undefined ) {
        let hConverted:Partial<IPAddress> = {};
        hConverted.IP = (hSocketEndpointAddress as TcpEndpointAddress).ip;
        hConverted.Port = (hSocketEndpointAddress as TcpEndpointAddress).port;
        return ( hConverted as IPAddress );
    } else { // ( (hSocketEndpointAddress as UnixEndpointAddress).path != undefined )
        let hConverted:Partial<UnixAddress> = {};
        hConverted.Path = (hSocketEndpointAddress as UnixEndpointAddress).path;
        return ( hConverted as UnixAddress );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket Interfaces : Connect Options
interface ConnectOptionsTCP {
    Family?:SocketFamily.IPv4 | SocketFamily.IPv6; // Default = Determine from Host
    Host?:string;    // Default = 'localhost'
    Port?:number;
    UseTLS?:boolean; // Default = false
}
interface ConnectOptionsUNIX {
    Family:SocketFamily.UNIX;
    Type?:SocketUNIXType; // Default = Path
    Path:string;
    UseTLS?:boolean; // Default = false
}

type ConnectOptions = ConnectOptionsTCP | ConnectOptionsUNIX;

function _ConvertFrom_ConnectOptions( hConnectOptions:ConnectOptions ):SocketConnectOptions {
    if ( hConnectOptions.Family == SocketFamily.UNIX ) {
        let hConverted:Partial<UnixConnectOptions> = {};
        hConverted.family = (hConnectOptions as ConnectOptionsUNIX).Family;
        hConverted.type = (hConnectOptions as ConnectOptionsUNIX).Type;
        hConverted.path = (hConnectOptions as ConnectOptionsUNIX).Path;
        hConverted.tls = (hConnectOptions as ConnectOptionsUNIX).UseTLS;
        return ( hConverted as UnixConnectOptions );
    } else {
        let hConverted:Partial<TcpConnectOptions> = {};
        hConverted.family = (hConnectOptions as ConnectOptionsTCP).Family;
        hConverted.host = (hConnectOptions as ConnectOptionsTCP).Host;
        hConverted.port = (hConnectOptions as ConnectOptionsTCP).Port;
        hConverted.tls = (hConnectOptions as ConnectOptionsTCP).UseTLS;
        return ( hConverted as TcpConnectOptions );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket Interfaces : Listen Options
interface ListenOptionsTCP {
    Family?:SocketFamily.IPv4 | SocketFamily.IPv6; // Default = Listen on both
    Host?:string;    // Default = Listen all interfaces
    Port?:number;    // Default = Random port
    BackLog?:number; // Default = 10
}
interface ListenOptionsUNIX {
    Family:SocketFamily.UNIX;
    Type?:SocketUNIXType; // Default = Path
    Path:string;
    BackLog?:number; // Default = 10
}

type ListenOptions = ListenOptionsTCP | ListenOptionsUNIX;

function _ConvertFrom_ListenOptions( hListenOptions:ListenOptions ):SocketListenOptions {
    if ( hListenOptions.Family == SocketFamily.UNIX ) {
        let hConverted:Partial<UnixListenOptions> = {};
        hConverted.family = (hListenOptions as ListenOptionsUNIX).Family;
        hConverted.type = (hListenOptions as ListenOptionsUNIX).Type;
        hConverted.path = (hListenOptions as ListenOptionsUNIX).Path;
        hConverted.backlog = (hListenOptions as ListenOptionsUNIX).BackLog;
        return ( hConverted as UnixListenOptions );
    } else {
        let hConverted:Partial<TcpListenOptions> = {};
        hConverted.family = (hListenOptions as ListenOptionsTCP).Family;
        hConverted.host = (hListenOptions as ListenOptionsTCP).Host;
        hConverted.port = (hListenOptions as ListenOptionsTCP).Port;
        hConverted.backlog = (hListenOptions as ListenOptionsTCP).BackLog;
        return ( hConverted as TcpListenOptions );
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The Socket class
class Socket {
    // Members
    private m_hSocket:SocketConnection | SocketListener;
    
    // Constructor
	constructor( hSocket:SocketConnection | SocketListener ) {
		this.m_hSocket = hSocket;
    }
    static Connect( hConnectOptions:ConnectOptions ):Promise<Socket> {
        let hPromise:Promise<SocketConnection> = global.Socket.connect( _ConvertFrom_ConnectOptions(hConnectOptions) );
        return new Promise<Socket>( function( resolve, reject ):void {
            hPromise.then(
                function( hResult:SocketConnection ):void { resolve( new Socket(hResult) ); },
                function( strError:string ):void          { reject( strError ); }
            );
        });
    }
    static Listen( hListenOptions:ListenOptions ):Promise<Socket> {
        let hPromise:Promise<SocketListener> = global.Socket.listen( _ConvertFrom_ListenOptions(hListenOptions) );
        return new Promise<Socket>( function( resolve, reject ):void {
            hPromise.then(
                function( hResult:SocketListener ):void { resolve( new Socket(hResult) ); },
                function( strError:string ):void        { reject( strError ); }
            );
        });
    }

    // Properties
    static GetType( hHandle:number ):SocketType {
        return SocketType[global.Socket.type(hHandle) as keyof typeof SocketType];
    }
    static GetLocalAddress( hHandle:number ):NetAddress | null {
        let hAddress:SocketEndpointAddress | null = global.Socket.localAddress( hHandle );
        if ( hAddress == null )
            return null;
        return _ConvertTo_NetAddress( hAddress );
    }

    // Methods
    Close():void { this.m_hSocket.close(); }

    // Connection Methods
    GetInputStream():IStream {
        return new IStream( (this.m_hSocket as SocketConnection).input );
    }
    GetOutputStream():OStream {
        return new OStream( (this.m_hSocket as SocketConnection).output );
    }

    ToggleDelay( bEnable:boolean ):void {
        (this.m_hSocket as SocketConnection).setNoDelay( bEnable );
    }

    // Listener Methods
    GetPort():number { return (this.m_hSocket as TcpListener).port; }
    GetPath():string { return (this.m_hSocket as UnixListener).path; }

    Accept():Promise<Socket> {
        let hPromise:Promise<SocketConnection> = (this.m_hSocket as SocketListener).accept();
        return new Promise<Socket>( function( resolve, reject ):void {
            hPromise.then(
                function( hResult:SocketConnection ):void { resolve( new Socket(hResult) ); },
                function( strError:string ):void          { reject( strError ); }
            );
        });
    }
}

