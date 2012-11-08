goatse
======

http ssh relay for use with chromium hterm session

This is an attempt to reverse-engineer googles javascript code for their http-ssh relays for the purpose of 
creating my own ssh relay. The relays themselves are proprietary, however the connection scripts are not.

Below is the code from nassh_google_relay.js

   1 // Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
   2 // Use of this source code is governed by a BSD-style license that can be
   3 // found in the LICENSE file.
   4 
   5 'use strict';
   6 
   7 lib.rtdep('lib.f');
   8 
   9 /**
  10  * This file contains the support required to make connections to Google's
  11  * HTTP-to-SSH relay.
  12  *
  13  * See Also: nassh_stream_google_relay.js, which defines the hterm stream class
  14  * for this relay mechanism.
  15  *
  16  * The relay is only available within Google at the moment.  If you'd like
  17  * to create one of your own though, you could follow the same conventions
  18  * and have a client ready to go.
  19  *
  20  * The connection looks like this...
  21  *
  22  *  +------+   +-------+   +---------------+
  23  *  | USER |   | PROXY |   | COOKIE_SERVER |
  24  *  +------+   +-------+   +---------------+
  25  *
  26  *                         +-----------+
  27  *                         | SSH_RELAY |
  28  *                         +-----------+
  29  *
  30  * 1. User specifies that they'd like to make their ssh connection through a
  31  *    web server.  In this code, that web server is called the 'proxy', since
  32  *    it happens to be an HTTP proxy.
  33  *
  34  * 2. We redirect to the 'http://HOST:8022/cookie?ext=RETURN_TO'.
  35  *
  36  *      HOST is the user-specified hostname for the proxy.  Port 8022 on the
  37  *      proxy is assumed to be the cookie server.
  38  *
  39  *      RETURN_TO is the location that the cookie server should redirect to
  40  *      when the cookie server is satisfied.
  41  *
  42  *    This connects us to the 'cookie server', which can initiate a
  43  *    single-sign-on flow if necessary.  It's also responsible for telling us
  44  *    which SSH_RELAY server we should talk to for the actual ssh read/write
  45  *    operations.
  46  *
  47  * 3. When the cookie server is done with its business it redirects to
  48  *    /html/google_relay.html#USER@RELAY_HOST.
  49  *
  50  *    The RELAY_HOST is the host that we should use as the socket relay.
  51  *    This allows the cookie server to choose a relay server from a
  52  *    pool of hosts.  This is *just* the host name, it's up to clients to
  53  *    know the uri scheme and port number.
  54  *
  55  *    The RELAY_HOST is expected to respond to requests for /proxy, /write,
  56  *    and /read.
  57  *
  58  * 4. We send a request to /proxy, which establishes the ssh session with
  59  *    a remote host.
  60  *
  61  * 5. We establish a hanging GET on /read.  If the read completes with a
  62  *    HTTP 200 OK then we consider the response entity as web-safe base 64
  63  *    encoded data.  If the read completes with an HTTP 401 GONE, we assume
  64  *    the relay has discarded the ssh session.  Any other responses are
  65  *    ignored.  The /read request is reestablished for anything other than
  66  *    401.
  67  *
  68  * 6. Writes are queued up and sent to /write.
  69  */
  70 
  71 nassh.GoogleRelay = function(io, proxy, options) {
  72   this.io = io;
  73   this.proxy = proxy;
  74   this.useSecure = options.search('--use-ssl') != -1;
  75   this.useWebsocket = !(options.search('--use-xhr') != -1);
  76   this.relayServer = null;
  77   this.relayServerSocket = null;
  78 };
  79 
  80 /**
  81  * The pattern for the cookie server's url.
  82  */
  83 nassh.GoogleRelay.prototype.cookieServerPattern =
  84     '%(protocol)://%(host):8022/cookie?ext=%encodeURIComponent(return_to)' +
  85     '&path=html/nassh_google_relay.html';
  86 
  87 /**
  88  * The pattern for XHR relay server's url.
  89  *
  90  * We'll be appending 'proxy', 'read' and 'write' to this as necessary.
  91  */
  92 nassh.GoogleRelay.prototype.relayServerPattern =
  93     '%(protocol)://%(host):8023/';
  94 
  95 /**
  96  * The pattern for WebSocket relay server's url.
  97  */
  98 nassh.GoogleRelay.prototype.relayServerSocketPattern =
  99     '%(protocol)://%(host):8022/';
 100 
 101 nassh.GoogleRelay.prototype.redirect = function(opt_resumePath) {
 102   var resumePath = opt_resumePath ||
 103       document.location.href.substr(document.location.origin.length);
 104 
 105   // Save off our destination in session storage before we leave for the
 106   // proxy page.
 107   sessionStorage.setItem('googleRelay.resumePath', resumePath);
 108 
 109   document.location = lib.f.replaceVars(
 110       this.cookieServerPattern,
 111       { host: this.proxy,
 112         protocol: this.useSecure ? 'https' : 'http',
 113         // This returns us to nassh_google_relay.html so we can pick the relay
 114         // host out of the reply.  From there we continue on to the resumePath.
 115         return_to:  document.location.host
 116       });
 117 };
 118 
 119 /**
 120  * Initialize this relay object.
 121  *
 122  * If we haven't just come back from the cookie server, then this function
 123  * will redirect to the cookie server and return false.
 124  *
 125  * If we have just come back from the cookie server, then we'll return true.
 126  */
 127 nassh.GoogleRelay.prototype.init = function(opt_resumePath) {
 128   var resumePath = opt_resumePath ||
 129       document.location.href.substr(document.location.origin.length);
 130 
 131   // This session storage item is created by /html/nassh_google_relay.html
 132   // if we succeed at finding a relay host.
 133   var relayHost = sessionStorage.getItem('googleRelay.relayHost');
 134   if (relayHost) {
 135     var expectedResumePath =
 136         sessionStorage.getItem('googleRelay.resumePath');
 137     if (expectedResumePath == resumePath) {
 138       var protocol = this.useSecure ? 'https' : 'http';
 139       var pattern = this.useWebsocket ? this.relayServerSocketPattern :
 140                                         this.relayServerPattern;
 141       this.relayServer = lib.f.replaceVars(pattern,
 142           {host: relayHost, protocol: protocol});
 143       if (this.useWebsocket) {
 144         protocol = this.useSecure ? 'wss' : 'ws';
 145         this.relayServerSocket = lib.f.replaceVars(pattern,
 146             {host: relayHost, protocol: protocol});
 147       }
 148     } else {
 149       // If everything is ok, this should be the second time we've been asked
 150       // to do the same init.  (The first time would have redirected.)  If this
 151       // init specifies a different resumePath, then something is probably
 152       // wrong.
 153       console.warn('Destination mismatch: ' + expectedResumePath + ' != ' +
 154                    resumePath);
 155       this.relayServer = null;
 156     }
 157   }
 158 
 159   sessionStorage.removeItem('googleRelay.relayHost');
 160   sessionStorage.removeItem('googleRelay.resumePath');
 161 
 162   if (this.relayServer)
 163     return true;
 164 
 165   return false;
 166 };
 167 
 168 /**
 169  * Return an nassh.Stream object that will handle the socket stream
 170  * for this relay.
 171  */
 172 nassh.GoogleRelay.prototype.openSocket = function(fd, host, port, onOpen) {
 173   var streamClass = this.useWebsocket ? nassh.Stream.GoogleRelayWS :
 174                                         nassh.Stream.GoogleRelayXHR;
 175   return nassh.Stream.openStream(streamClass,
 176       fd, {relay: this, host: host, port: port}, onOpen);
 177 };