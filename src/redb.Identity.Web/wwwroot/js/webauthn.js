// MFA-3: WebAuthn browser ceremony interop for Blazor.
// Exposes window.redbWebAuthn.{createCredential, getAssertion, isSupported}.
// Backend uses Fido2NetLib which serializes byte[] as base64url; we convert
// base64url <-> ArrayBuffer here so the page never has to deal with binary.
(function () {
    'use strict';

    function b64urlToBytes(s) {
        if (s == null) return null;
        s = String(s).replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4;
        if (pad === 2) s += '==';
        else if (pad === 3) s += '=';
        else if (pad === 1) throw new Error('Invalid base64url string');
        const bin = atob(s);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function b64urlToBuffer(s) {
        const u8 = b64urlToBytes(s);
        return u8 ? u8.buffer : null;
    }

    function bufferToB64url(buf) {
        const u8 = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function isSupported() {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    }

    // options: the `options` object returned by /me/webauthn/register/begin
    //   (Fido2NetLib CredentialCreateOptions, camelCase, base64url buffers).
    async function createCredential(options) {
        if (!isSupported()) throw new Error('WebAuthn is not supported in this browser.');

        const publicKey = {
            rp: options.rp,
            user: {
                id: b64urlToBuffer(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName
            },
            challenge: b64urlToBuffer(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            attestation: options.attestation,
            authenticatorSelection: options.authenticatorSelection,
            extensions: options.extensions
        };

        if (Array.isArray(options.excludeCredentials)) {
            publicKey.excludeCredentials = options.excludeCredentials.map(c => ({
                id: b64urlToBuffer(c.id),
                type: c.type,
                transports: c.transports
            }));
        }

        const cred = await navigator.credentials.create({ publicKey });
        if (!cred) throw new Error('navigator.credentials.create returned null.');

        return {
            id: cred.id,
            rawId: bufferToB64url(cred.rawId),
            type: cred.type,
            response: {
                attestationObject: bufferToB64url(cred.response.attestationObject),
                clientDataJson: bufferToB64url(cred.response.clientDataJSON)
            },
            extensions: typeof cred.getClientExtensionResults === 'function'
                ? cred.getClientExtensionResults()
                : {}
        };
    }

    // options: the `options` object returned by /mfa/webauthn/begin (assertion).
    async function getAssertion(options) {
        if (!isSupported()) throw new Error('WebAuthn is not supported in this browser.');

        const publicKey = {
            challenge: b64urlToBuffer(options.challenge),
            timeout: options.timeout,
            rpId: options.rpId,
            userVerification: options.userVerification,
            extensions: options.extensions
        };

        if (Array.isArray(options.allowCredentials)) {
            publicKey.allowCredentials = options.allowCredentials.map(c => ({
                id: b64urlToBuffer(c.id),
                type: c.type,
                transports: c.transports
            }));
        }

        const cred = await navigator.credentials.get({ publicKey });
        if (!cred) throw new Error('navigator.credentials.get returned null.');

        return {
            id: cred.id,
            rawId: bufferToB64url(cred.rawId),
            type: cred.type,
            response: {
                authenticatorData: bufferToB64url(cred.response.authenticatorData),
                clientDataJson: bufferToB64url(cred.response.clientDataJSON),
                signature: bufferToB64url(cred.response.signature),
                userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : null
            },
            extensions: typeof cred.getClientExtensionResults === 'function'
                ? cred.getClientExtensionResults()
                : {}
        };
    }

    window.redbWebAuthn = { createCredential, getAssertion, isSupported };
})();
