#!/usr/bin/env node

// Configuration Variables
const SERVER_PORT = process.env.SERVER_PORT || 8443; // only udp 
const PASSWORD = process.env.PASSWORD || '0a6568ff-ea3c-4271-9020-450560e10d63';  // your uuid

// sub  Configuration
const PORT = process.env.PORT || 3000;            // http port
const DOMAIN = process.env.DOMAIN || '127.0.0.1'; // domain or ip
const SUB_PATH = process.env.SUB_PATH || 'sub';   // sub path

const http = require('http');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const net = require('net');
const crypto = require('crypto');
const dns = require('dns');
const { EventEmitter } = require('events');

// Configure DNS servers
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
dns.setServers(DNS_SERVERS);
// ============================================================================
// AnyTLS Session Protocol Constants
// ============================================================================

const CMD_WASTE = 0;
const CMD_SYN = 1;
const CMD_PSH = 2;
const CMD_FIN = 3;
const CMD_SETTINGS = 4;
const CMD_ALERT = 5;
const CMD_UPDATE_PADDING = 6;
const CMD_SYNACK = 7;
const CMD_HEART_REQUEST = 8;
const CMD_HEART_RESPONSE = 9;
const CMD_SERVER_SETTINGS = 10;
const HEADER_SIZE = 7;

const MAX_FRAME_SIZE = 32768; // 32KB per frame for better flow control

// ============================================================================
// AnyTLS Stream
// ============================================================================

class AnyTLSStream extends EventEmitter {
    constructor(id, session) {
        super();
        this.id = id;
        this.session = session;
        this.closed = false;
        this.writeQueue = [];
        this.ready = false;
    }

    write(data, callback) {
        if (this.closed) {
            if (callback) callback(new Error('Stream closed'));
            return false;
        }
        
        if (!this.ready) {
            this.writeQueue.push({ data, callback });
            return true;
        }
        
        // Split large data into chunks and write them
        if (data.length > MAX_FRAME_SIZE) {
            const chunks = [];
            for (let i = 0; i < data.length; i += MAX_FRAME_SIZE) {
                chunks.push(data.slice(i, i + MAX_FRAME_SIZE));
            }
            
            let completed = 0;
            let hasError = false;
            
            chunks.forEach((chunk) => {
                this.session._writeDataFrame(this.id, chunk, (err) => {
                    if (err && !hasError) {
                        hasError = true;
                        if (callback) callback(err);
                    }
                    completed++;
                    if (completed === chunks.length && !hasError) {
                        if (callback) callback();
                    }
                });
            });
            
            return true;
        }
        
        return this.session._writeDataFrame(this.id, data, callback);
    }

    setReady() {
        this.ready = true;
        while (this.writeQueue.length > 0) {
            const { data, callback } = this.writeQueue.shift();
            this.write(data, callback);
        }
    }

    end() {
        if (!this.closed) {
            this.closed = true;
            this.session._closeStream(this.id);
            this.emit('end');
        }
    }

    destroy() {
        this.end();
    }

    _handleData(data) {
        if (!this.closed) {
            this.emit('data', data);
        }
    }

    _handleClose() {
        if (!this.closed) {
            this.closed = true;
            this.emit('end');
            this.emit('close');
        }
    }
}

// ============================================================================
// AnyTLS Session
// ============================================================================

class AnyTLSSession extends EventEmitter {
    constructor(connection) {
        super();
        this.connection = connection;
        this.streams = new Map();
        this.closed = false;
        this.buffer = Buffer.alloc(0);
        this.receivedSettings = false;
        this.active = false;

        if (connection.setNoDelay) {
            connection.setNoDelay(true);
        }
    }

    activate() {
        if (this.active) return;
        this.active = true;

        this.connection.on('data', (data) => this._handleData(data));
        this.connection.on('close', () => this._handleClose());
        this.connection.on('error', (err) => this.emit('error', err));
    }

    _handleData(data) {
        this.buffer = Buffer.concat([this.buffer, data]);

        while (this.buffer.length >= HEADER_SIZE) {
            const cmd = this.buffer.readUInt8(0);
            const streamId = this.buffer.readUInt32BE(1);
            const length = this.buffer.readUInt16BE(5);

            if (this.buffer.length < HEADER_SIZE + length) {
                break;
            }

            const payload = this.buffer.slice(HEADER_SIZE, HEADER_SIZE + length);
            this.buffer = this.buffer.slice(HEADER_SIZE + length);

            this._processFrame(cmd, streamId, payload);
        }
    }

    _processFrame(cmd, streamId, payload) {
        switch (cmd) {
            case CMD_SETTINGS:
                this._handleSettings(payload);
                break;
            case CMD_SYN:
                this._handleSyn(streamId);
                break;
            case CMD_PSH:
                this._handlePush(streamId, payload);
                break;
            case CMD_FIN:
                this._handleFin(streamId);
                break;
            case CMD_WASTE:
                break;
            case CMD_HEART_REQUEST:
                this._sendFrame(CMD_HEART_RESPONSE, streamId, Buffer.alloc(0));
                break;
        }
    }

    _handleSettings(payload) {
        if (this.receivedSettings) return;
        this.receivedSettings = true;
        this._sendFrame(CMD_SERVER_SETTINGS, 0, Buffer.from('v=2\n'));
    }

    _handleSyn(streamId) {
        if (!this.receivedSettings) {
            this._sendFrame(CMD_ALERT, 0, Buffer.from('client did not send its settings'));
            this.close();
            return;
        }

        if (this.streams.has(streamId)) return;

        const stream = new AnyTLSStream(streamId, this);
        this.streams.set(streamId, stream);
        this._sendFrame(CMD_SYNACK, streamId, Buffer.alloc(0));
        stream.setReady();
        this.emit('stream', stream);
    }

    _handlePush(streamId, data) {
        const stream = this.streams.get(streamId);
        if (stream) {
            stream._handleData(data);
        }
    }

    _handleFin(streamId) {
        const stream = this.streams.get(streamId);
        if (stream) {
            stream._handleClose();
            this.streams.delete(streamId);
        }
    }

    _sendFrame(cmd, streamId, data, callback) {
        if (this.closed) {
            if (callback) callback(new Error('Session closed'));
            return false;
        }

        if (data.length > 65535) {
            if (callback) callback(new Error('Frame too large'));
            return false;
        }

        const header = Buffer.alloc(HEADER_SIZE);
        header.writeUInt8(cmd, 0);
        header.writeUInt32BE(streamId, 1);
        header.writeUInt16BE(data.length, 5);

        const frame = Buffer.concat([header, data]);
        this.connection.write(frame, callback);
        return true;
    }

    _writeDataFrame(streamId, data, callback) {
        return this._sendFrame(CMD_PSH, streamId, data, callback);
    }

    _closeStream(streamId) {
        this._sendFrame(CMD_FIN, streamId, Buffer.alloc(0));
        this.streams.delete(streamId);
    }

    _handleClose() {
        if (this.closed) return;
        this.closed = true;
        
        for (const stream of this.streams.values()) {
            stream._handleClose();
        }
        this.streams.clear();
        this.emit('close');
    }

    close() {
        if (!this.closed) {
            this._handleClose();
            this.connection.end();
        }
    }
}

// ============================================================================
// SOCKS5 Address Parsing
// ============================================================================

function parseSocks5Address(stream, firstData, callback) {
    let buffer = firstData || Buffer.alloc(0);
    let headerRead = false;
    let handlerAttached = false;

    const cleanup = () => {
        if (handlerAttached) {
            stream.removeListener('data', onData);
        }
    };

    const tryParse = () => {
        if (headerRead || buffer.length < 1) return;

        const atyp = buffer.readUInt8(0);
        let addressLength = 0;

        if (atyp === 0x01) {
            addressLength = 1 + 4 + 2;
        } else if (atyp === 0x03) {
            if (buffer.length >= 2) {
                const domainLen = buffer.readUInt8(1);
                addressLength = 1 + 1 + domainLen + 2;
            }
        } else if (atyp === 0x04) {
            addressLength = 1 + 16 + 2;
        } else {
            cleanup();
            callback(new Error('Invalid address type: ' + atyp));
            return;
        }

        if (addressLength > 0 && buffer.length >= addressLength) {
            headerRead = true;
            cleanup();

            const addressData = buffer.slice(0, addressLength);
            const remaining = buffer.slice(addressLength);

            let host, port;
            if (atyp === 0x01) {
                host = `${addressData[1]}.${addressData[2]}.${addressData[3]}.${addressData[4]}`;
                port = addressData.readUInt16BE(5);
            } else if (atyp === 0x03) {
                const domainLen = addressData.readUInt8(1);
                host = addressData.slice(2, 2 + domainLen).toString();
                port = addressData.readUInt16BE(2 + domainLen);
            } else if (atyp === 0x04) {
                const parts = [];
                for (let i = 0; i < 16; i += 2) {
                    parts.push(addressData.readUInt16BE(1 + i).toString(16));
                }
                host = parts.join(':');
                port = addressData.readUInt16BE(17);
            }

            callback(null, { host, port }, remaining);
        }
    };

    const onData = (data) => {
        buffer = Buffer.concat([buffer, data]);
        tryParse();
    };

    tryParse();

    if (!headerRead) {
        handlerAttached = true;
        stream.on('data', onData);
    }
}

// ============================================================================
// Proxy Handler
// ============================================================================

function handleProxyStream(stream) {
    let remote = null;
    let addressParsed = false;
    let bufferedData = [];
    let remotePaused = false;
    let streamEnded = false;
    let remoteEnded = false;

    const handleFirstData = (data) => {
        if (addressParsed) return;
        
        parseSocks5Address(stream, data, (err, destination, remaining) => {
            if (err) {
                stream.destroy();
                return;
            }

            addressParsed = true;

            remote = net.createConnection({
                host: destination.host,
                port: destination.port,
                timeout: 60000
            });

            remote.setNoDelay(true);
            remote.setKeepAlive(true, 30000);

            let connected = false;

            remote.on('connect', () => {
                connected = true;

                if (remaining && remaining.length > 0) {
                    remote.write(remaining);
                }

                while (bufferedData.length > 0 && !remotePaused) {
                    const chunk = bufferedData.shift();
                    if (!remote.write(chunk)) {
                        remotePaused = true;
                    }
                }
            });

            remote.on('drain', () => {
                remotePaused = false;
                while (bufferedData.length > 0 && !remotePaused) {
                    const chunk = bufferedData.shift();
                    if (!remote.write(chunk)) {
                        remotePaused = true;
                    }
                }
            });

            remote.on('data', (data) => {
                if (!stream.closed && !streamEnded) {
                    stream.write(data, (err) => {
                        if (err && !remote.destroyed) {
                            remote.destroy();
                        }
                    });
                }
            });

            remote.on('end', () => {
                remoteEnded = true;
                if (!stream.closed && !streamEnded) {
                    stream.end();
                }
            });

            remote.on('error', (err) => {
                if (!stream.closed && !streamEnded) {
                    stream.destroy();
                }
            });

            remote.on('close', () => {
                if (!stream.closed && !streamEnded) {
                    stream.destroy();
                }
            });

            remote.on('timeout', () => {
                remote.destroy();
            });
        });
    };

    const handleData = (data) => {
        if (!addressParsed) {
            bufferedData.push(data);
        } else if (remote && !remote.destroyed) {
            if (remotePaused || bufferedData.length > 0) {
                bufferedData.push(data);
                // Limit buffer size to prevent memory issues
                if (bufferedData.length > 100) {
                    stream.destroy();
                    if (remote) remote.destroy();
                }
            } else {
                if (!remote.write(data)) {
                    remotePaused = true;
                }
            }
        }
    };

    let isFirstData = true;
    stream.on('data', (data) => {
        if (isFirstData) {
            isFirstData = false;
            handleFirstData(data);
        } else {
            handleData(data);
        }
    });

    stream.on('end', () => {
        streamEnded = true;
        if (remote && !remote.destroyed && !remoteEnded) {
            remote.end();
        }
    });

    stream.on('error', (err) => {
        if (remote && !remote.destroyed) {
            remote.destroy();
        }
    });

    stream.on('close', () => {
        if (remote && !remote.destroyed) {
            remote.destroy();
        }
    });
}

// ============================================================================
// TLS Certificate Generation
// ============================================================================

function generateSelfSignedCert() {
    const forge = require('node-forge');
    const pki = forge.pki;

    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
        name: 'commonName',
        value: 'anytls-server'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    return {
        key: pki.privateKeyToPem(keys.privateKey),
        cert: pki.certificateToPem(cert)
    };
}

// ============================================================================
// TLS Server
// ============================================================================

const passwordHash = crypto.createHash('sha256').update(PASSWORD).digest();

let tlsOptions;
try {
    const pems = generateSelfSignedCert();
    tlsOptions = {
        key: pems.key,
        cert: pems.cert,
        requestCert: false,
        rejectUnauthorized: false
    };
} catch (err) {
    console.error('node-forge not available, install it with: npm install node-forge');
    process.exit(1);
}

const server = tls.createServer(tlsOptions, (socket) => {
    let buffer = Buffer.alloc(0);
    let authenticated = false;
    let session = null;

    const onData = (data) => {
        if (!authenticated) {
            buffer = Buffer.concat([buffer, data]);
            
            if (buffer.length < 34) return;

            const clientPasswordHash = buffer.slice(0, 32);

            if (!clientPasswordHash.equals(passwordHash)) {
                socket.destroy();
                return;
            }

            const paddingLength = buffer.readUInt16BE(32);

            if (buffer.length < 34 + paddingLength) return;

            authenticated = true;

            const remainingData = buffer.slice(34 + paddingLength);
            buffer = Buffer.alloc(0);

            socket.removeListener('data', onData);

            session = new AnyTLSSession(socket);

            session.on('stream', (stream) => {
                handleProxyStream(stream);
            });

            session.on('error', () => {});
            session.on('close', () => {});

            session.activate();

            if (remainingData.length > 0) {
                session._handleData(remainingData);
            }
        }
    };

    socket.on('data', onData);
    socket.on('error', () => {});
    socket.on('close', () => {
        if (session) {
            session.close();
        }
    });
});


server.on('error', (err) => {
    console.error('AnyTLS Server error:', err);
    process.exit(1);
});

// HTTP server for serving public files and subscription info
const httpServer = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(indexPath, (err, data) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('hello world');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(data);
      }
    });
  } else if (req.url === '/' + SUB_PATH) {
    const subInfo = `anytls://${PASSWORD}@${DOMAIN}:${SERVER_PORT}?security=tls&sni=${DOMAIN}&fp=chrome&insecure=1&allowInsecure=1#Anytls`;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(subInfo);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  }
});

// Handle HTTP server errors
httpServer.on('error', (err) => {
    console.error('HTTP Server error:', err);
    process.exit(1);
});

// Start the AnyTLS server
server.listen(SERVER_PORT, '0.0.0.0', () => {
    console.log(`AnyTLS server listening on 0.0.0.0:${SERVER_PORT}`);
});

// Start the HTTP server
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`HTTP server listening on 0.0.0.0:${PORT}`);
});
