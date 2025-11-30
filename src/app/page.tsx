"use client";

/**
 * End-to-End Encrypted Chat PoC
 * * Architecture:
 * - Hybrid Encryption Scheme (RSA + AES)
 * - Key Exchange: RSA-OAEP (2048-bit, SHA-256)
 * - Message Encryption: AES-GCM (256-bit)
 * - Transport: Simulates a centralized server that only sees encrypted blobs
 */

import React, { useState, useEffect, useRef } from 'react';
import { Lock, Unlock, Send, Shield, RefreshCw, Terminal, Smartphone, Monitor, Activity, ArrowRight, ToggleLeft, ToggleRight } from 'lucide-react';

// Generates RSA-OAEP key pair (2048-bit) for asymmetric encryption.
// Used solely for exchanging the symmetric session key.
const generateKeyPair = async () => {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
};

// Generates ephemeral AES-GCM key (256-bit) for symmetric encryption.
// Used for encrypting the actual message payload.
const generateSessionKey = async () => {
    return await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
};

// Exports CryptoKey to Base64 string for transport/storage.
// default type: 'spki' for public keys.
const exportKey = async (key: CryptoKey, type: 'pkcs8' | 'spki' = 'spki') => {
    const exported = await window.crypto.subtle.exportKey(type, key);
    const exportedAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exported)));
    return exportedAsBase64.substring(0, 20) + '...'; // Truncated for UI display
};

// Wraps the AES session key using the receiver's RSA public key.
const encryptSessionKey = async (sessionKey: CryptoKey, publicKey: CryptoKey) => {
    const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
    return await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawKey
    );
};

// Unwraps the AES session key using the receiver's RSA private key.
const decryptSessionKey = async (encryptedSessionKey: ArrayBuffer, privateKey: CryptoKey) => {
    const rawKey = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedSessionKey
    );
    // Re-import raw bytes as AES-GCM key
    return await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );
};

// Encrypts plaintext using AES-GCM.
// Must generate a unique IV (Initialization Vector) for every operation.
const encryptMessage = async (text: string, sessionKey: CryptoKey) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    // 12 bytes is standard for AES-GCM IVs
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); 
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        data
    );
    
    return { encrypted, iv };
};

// Decrypts ciphertext using AES-GCM.
// Requires the exact IV used during encryption.
const decryptMessage = async (encryptedData: ArrayBuffer, iv: Uint8Array, sessionKey: CryptoKey) => {
    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            encryptedData
        );
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        // GCM includes an auth tag check; failure implies tampering or wrong key
        return "Decryption Failed - Auth/Key Error";
    }
};

type UserState = {
    name: string;
    type: 'mobile' | 'web';
    keyPair: CryptoKeyPair | null;
    publicKeyString: string;
    chatHistory: MessageDisplay[];
    sessionKey: CryptoKey | null; // Shared secret for current session
};

// Transport Layer Object
type MessagePacket = {
    id: string;
    sender: string;
    encryptedContent: ArrayBuffer;
    iv: Uint8Array;
    encryptedSessionKey?: ArrayBuffer; // Included only during initial handshake or re-keying
};

type MessageDisplay = {
    id: string;
    sender: string;
    text: string;
    isOwn: boolean;
    timestamp: Date;
};

export default function E2EEPrototype() {
    
    // Simulating two distinct clients with local state
    const [alice, setAlice] = useState<UserState>({
        name: 'Alice',
        type: 'mobile',
        keyPair: null,
        publicKeyString: '',
        chatHistory: [],
        sessionKey: null,
    });

    const [bob, setBob] = useState<UserState>({
        name: 'Bob',
        type: 'web',
        keyPair: null,
        publicKeyString: '',
        chatHistory: [],
        sessionKey: null,
    });

    // Simulating server-side logs (Man-in-the-Middle view)
    const [networkLog, setNetworkLog] = useState<
        { id: string; type: string; payload: string; from: string }[]
    >([]);

    const [aliceInput, setAliceInput] = useState('');
    const [bobInput, setBobInput] = useState('');
    const [isInitializing, setIsInitializing] = useState(false);
    
    // New State for Expanded Logging
    const [expandedLogging, setExpandedLogging] = useState(false);

    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        initializeKeys();
    }, []);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [networkLog]);

    const logNetwork = (type: string, payload: string, from: string) => {
        setNetworkLog((prev) => [
            ...prev,
            { id: Math.random().toString(36), type, payload, from },
        ]);
    };

    // Initialize RSA identities for both clients on mount
    const initializeKeys = async () => {
        setIsInitializing(true);

        const aliceKeys = await generateKeyPair();
        const alicePubStr = await exportKey(aliceKeys.publicKey);
        
        // Log Alice Connection
        logNetwork('CONN_ESTABLISHED', `Client [${alice.name}] connected via Secure Socket`, 'Server');
        logNetwork('PUB_KEY_UPLOAD', `[RSA-OAEP-2048] Received Public Key (${alicePubStr.length} bytes)`, alice.name);

        const bobKeys = await generateKeyPair();
        const bobPubStr = await exportKey(bobKeys.publicKey);

        // Log Bob Connection
        logNetwork('CONN_ESTABLISHED', `Client [${bob.name}] connected via Secure Socket`, 'Server');
        logNetwork('PUB_KEY_UPLOAD', `[RSA-OAEP-2048] Received Public Key (${bobPubStr.length} bytes)`, bob.name);

        setAlice((prev) => ({ ...prev, keyPair: aliceKeys, publicKeyString: alicePubStr }));
        setBob((prev) => ({ ...prev, keyPair: bobKeys, publicKeyString: bobPubStr }));

        setIsInitializing(false);
    };

    const handleSendMessage = async (
        sender: UserState,
        setSender: React.Dispatch<React.SetStateAction<UserState>>,
        receiver: UserState,
        setReceiver: React.Dispatch<React.SetStateAction<UserState>>,
        text: string,
        setInput: (s: string) => void
    ) => {
        if (!text.trim() || !sender.keyPair || !receiver.keyPair) return;

        let currentSessionKey = sender.sessionKey;
        let encryptedSessionKeyBundle: ArrayBuffer | undefined = undefined;

        // Check if active session exists. If not, perform handshake.
        if (!currentSessionKey) {
            // 1. Generate symmetric key
            currentSessionKey = await generateSessionKey();

            // 2. Wrap symmetric key with receiver's public key
            encryptedSessionKeyBundle = await encryptSessionKey(currentSessionKey, receiver.keyPair.publicKey);

            // Update sender state
            setSender(prev => ({ ...prev, sessionKey: currentSessionKey }));
        }

        // 3. Encrypt payload with symmetric key
        const { encrypted, iv } = await encryptMessage(text, currentSessionKey!);

        // 4. Construct packet for transport
        const packetId = Math.random().toString(36).substring(2, 9).toUpperCase();
        const packet: MessagePacket = {
            id: packetId,
            sender: sender.name,
            encryptedContent: encrypted,
            iv: iv,
            encryptedSessionKey: encryptedSessionKeyBundle,
        };

        // --- SERVER LOGGING ---
        const b64Content = window.btoa(String.fromCharCode(...new Uint8Array(encrypted)));

        if (expandedLogging) {
            // EXPANDED MODE: Verbose breakdown
            // 1. Packet Receipt
            logNetwork('PACKET_IN', `Received Packet #${packetId} from ${sender.name}`, 'Server');
            
            // 2. Metadata Inspection (IV & Size)
            const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
            logNetwork('META_INSPECT', `IV: 0x${ivHex.substring(0, 8)}... | Payload: ${encrypted.byteLength} bytes`, 'Server');

            // 3. Encrypted Content Visualization
            logNetwork('PAYLOAD', `[AES-GCM Ciphertext] ${b64Content.substring(0, 30)}...`, sender.name);

            // 4. Handshake/Key Exchange Logic
            if (encryptedSessionKeyBundle) {
                logNetwork('HANDSHAKE', `[RSA-OAEP] Detected Encrypted Session Key Bundle (${encryptedSessionKeyBundle.byteLength} bytes)`, sender.name);
                logNetwork('INFO', `New Session Key negotiation for ${receiver.name}`, 'Server');
            }

            // 5. Routing
            logNetwork('ROUTING', `Forwarding Packet #${packetId} to Client [${receiver.name}]`, 'Server');

        } else {
            // STANDARD MODE: Concise summary
            logNetwork('MSG_PACKET', `[AES-GCM] ${b64Content.substring(0, 30)}...`, sender.name);
            if (encryptedSessionKeyBundle) {
                logNetwork('KEY_EXCHANGE', `[RSA-OAEP] Encrypted Session Key attached`, sender.name);
            }
        }
        
        // --- END SERVER LOGGING ---

        // Optimistic UI update
        const newMessage: MessageDisplay = {
            id: packet.id,
            sender: sender.name,
            text: text,
            isOwn: true,
            timestamp: new Date(),
        };
        setSender(prev => ({ ...prev, chatHistory: [...prev.chatHistory, newMessage] }));
        setInput('');

        // Simulate transport
        receiveMessage(packet, receiver, setReceiver);
    };

    const receiveMessage = async (
        packet: MessagePacket,
        receiver: UserState,
        setReceiver: React.Dispatch<React.SetStateAction<UserState>>
    ) => {
        let sessionKey = receiver.sessionKey;

        // Handle Key Exchange / Rotation
        if (packet.encryptedSessionKey) {
            if (!receiver.keyPair) return;
            try {
                // Unwrap session key with private key
                sessionKey = await decryptSessionKey(packet.encryptedSessionKey, receiver.keyPair.privateKey);
                setReceiver(prev => ({ ...prev, sessionKey }));
            } catch (e) {
                console.error("Failed to decrypt session key", e);
                return;
            }
        }

        if (!sessionKey) {
            console.error("No session key available");
            return;
        }

        // Decrypt payload
        const decryptedText = await decryptMessage(packet.encryptedContent, packet.iv, sessionKey);

        const receivedMsg: MessageDisplay = {
            id: packet.id,
            sender: packet.sender,
            text: decryptedText,
            isOwn: false,
            timestamp: new Date(),
        };

        setReceiver(prev => ({ ...prev, chatHistory: [...prev.chatHistory, receivedMsg] }));
    };

    return (
        <div className="min-h-screen bg-slate-900 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white p-4 lg:p-8">

            <div className="max-w-7xl mx-auto mb-8 text-center space-y-2">
                <h1 className="text-3xl font-bold flex items-center justify-center gap-3">
                    <Shield className="w-8 h-8 text-indigo-400" />
                    End-to-End Encrypted Chat
                </h1>
                <p className="text-slate-400 text-sm max-w-2xl mx-auto">
                    Hybrid Encryption Implementation (RSA-OAEP + AES-GCM)
                </p>
            </div>

            <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6 h-[800px]">

                {/* Alice Client */}
                <DeviceFrame
                    user={alice}
                    inputValue={aliceInput}
                    setInputValue={setAliceInput}
                    onSend={() => handleSendMessage(alice, setAlice, bob, setBob, aliceInput, setAliceInput)}
                    isInitializing={isInitializing}
                    icon={<Smartphone className="w-5 h-5" />}
                    colorClass="border-pink-500/30 bg-pink-950/10"
                    headerColor="text-pink-400"
                />

                {/* Server Logs */}
                <div className="flex flex-col bg-slate-950 rounded-2xl border border-slate-800 shadow-2xl overflow-hidden order-last lg:order-none h-[300px] lg:h-auto">
                    <div className="p-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <Terminal className="w-5 h-5 text-emerald-400" />
                            <span className="font-mono font-bold text-emerald-400">Server Log</span>
                        </div>
                        
                        {/* HEADER CONTROLS */}
                        <div className="flex items-center gap-4">
                            {/* Toggle Switch */}
                            <button 
                                onClick={() => setExpandedLogging(!expandedLogging)}
                                className="flex items-center gap-2 text-xs text-slate-500 hover:text-indigo-400 transition-colors focus:outline-none"
                                title={expandedLogging ? "Disable Verbose Logging" : "Enable Verbose Logging"}
                            >
                                {expandedLogging ? 
                                    <ToggleRight className="w-5 h-5 text-indigo-400" /> : 
                                    <ToggleLeft className="w-5 h-5" />
                                }
                                <span className={expandedLogging ? "text-indigo-400 font-medium" : ""}>Debug Mode</span>
                            </button>

                            <div className="flex items-center gap-2 text-xs text-slate-500 border-l border-slate-800 pl-4">
                                <Activity className="w-3 h-3 text-emerald-400 animate-pulse" />
                                Listening
                            </div>
                        </div>
                    </div>
                    <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-3 custom-scrollbar">
                        {networkLog.length === 0 && (
                            <div className="text-slate-600 text-center mt-10 italic">
                                Waiting for packets...
                            </div>
                        )}
                        {networkLog.map((log) => (
                            <div key={log.id} className="border-l-2 border-slate-700 pl-3 py-1 animate-in fade-in slide-in-from-left-2 duration-300">
                                <div className="flex items-center justify-between text-slate-500 mb-1">
                                    <span className="font-bold text-indigo-400">{log.type}</span>
                                    <span className="text-slate-600">{log.from}</span>
                                </div>
                                <div className="break-all text-slate-400 opacity-70">
                                    {log.payload}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Bob Client */}
                <DeviceFrame
                    user={bob}
                    inputValue={bobInput}
                    setInputValue={setBobInput}
                    onSend={() => handleSendMessage(bob, setBob, alice, setAlice, bobInput, setBobInput)}
                    isInitializing={isInitializing}
                    icon={<Monitor className="w-5 h-5" />}
                    colorClass="border-cyan-500/30 bg-cyan-950/10"
                    headerColor="text-cyan-400"
                />

            </div>
        </div>
    );
}

const DeviceFrame = ({
                         user,
                         inputValue,
                         setInputValue,
                         onSend,
                         isInitializing,
                         icon,
                         colorClass,
                         headerColor
                     }: {
    user: UserState,
    inputValue: string,
    setInputValue: (s: string) => void,
    onSend: () => void,
    isInitializing: boolean,
    icon: React.ReactNode,
    colorClass: string,
    headerColor: string
}) => {
    const chatEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [user.chatHistory]);

    return (
        <div className={`flex flex-col rounded-3xl border-2 shadow-2xl overflow-hidden h-full ${colorClass}`}>
            
            <div className="p-4 bg-slate-900/50 backdrop-blur-md border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-full bg-slate-800 ${headerColor}`}>
                        {icon}
                    </div>
                    <div>
                        <h3 className={`font-bold ${headerColor}`}>{user.name}</h3>
                        <div className="flex items-center gap-1.5 text-xs text-slate-400">
                            <span className={`w-1.5 h-1.5 rounded-full ${user.keyPair ? 'bg-emerald-500' : 'bg-yellow-500'}`} />
                            {user.keyPair ? 'Secure Connection' : 'Generating Keys...'}
                        </div>
                    </div>
                </div>
                {user.sessionKey ? <Lock className="w-4 h-4 text-emerald-500" /> : <Unlock className="w-4 h-4 text-slate-600" />}
            </div>

            <div className="px-4 py-2 bg-black/20 text-[10px] text-slate-500 font-mono border-b border-white/5 flex flex-col gap-1">
                <div className="flex justify-between">
                    <span>PUB_KEY:</span>
                    <span>{user.publicKeyString || 'Generating...'}</span>
                </div>
                <div className="flex justify-between text-emerald-500/70">
                    <span>SESSION_KEY:</span>
                    <span>{user.sessionKey ? 'ESTABLISHED (AES-256)' : 'WAITING FOR HANDSHAKE'}</span>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-900/30">
                {isInitializing ? (
                    <div className="h-full flex flex-col items-center justify-center text-slate-500 gap-2">
                        <RefreshCw className="w-6 h-6 animate-spin" />
                        <span className="text-sm">Generating 2048-bit RSA Keys...</span>
                    </div>
                ) : user.chatHistory.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-2 opacity-50">
                        <Shield className="w-12 h-12" />
                        <p className="text-sm">Messages are end-to-end encrypted.</p>
                    </div>
                ) : (
                    user.chatHistory.map((msg) => (
                        <div key={msg.id} className={`flex ${msg.isOwn ? 'justify-end' : 'justify-start'}`}>
                            <div className={`max-w-[80%] rounded-2xl px-4 py-2 text-sm shadow-sm ${
                                msg.isOwn
                                    ? 'bg-indigo-600 text-white rounded-br-none'
                                    : 'bg-slate-700 text-slate-100 rounded-bl-none'
                            }`}>
                                {msg.text}
                                <div className={`text-[9px] mt-1 text-right ${msg.isOwn ? 'text-indigo-200' : 'text-slate-400'}`}>
                                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </div>
                            </div>
                        </div>
                    ))
                )}
                <div ref={chatEndRef} />
            </div>

            <div className="p-3 bg-slate-900 border-t border-white/5">
                <form
                    onSubmit={(e) => { e.preventDefault(); onSend(); }}
                    className="flex gap-2"
                >
                    <input
                        type="text"
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder="Type a secure message..."
                        className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50 placeholder:text-slate-500"
                    />
                    <button
                        type="submit"
                        disabled={!inputValue.trim() || isInitializing}
                        className="p-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-xl text-white transition-colors"
                    >
                        <Send className="w-5 h-5" />
                    </button>
                </form>
            </div>
        </div>
    );
};