import crypto from 'node:crypto';

const importPublicKeyAsCryptoKey = async (
    publicKey: BufferSource,
): Promise<CryptoKey | null> => {
    try {
        const key = await crypto.subtle.importKey(
            'spki',
            publicKey,
            {
                name: 'ECDSA',
                namedCurve: 'P-256',
            },
            true,
            ['verify'],
        );
        return key;
    } catch (e) {
        console.error('PUBLIC_KEY_CANT_BE_PARSED_AS_CRYPTO_KEY', e);
        return null;
    }
};

async function main() {
    // Original registration response (public key)
    const publicKey = Buffer.from(
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzpSOan1zA3rWiU712rbWQPbVdV4JCIudxMUkgjwg0umPAaDEIUorEEX_0VaRf702_r6nWxrRywKvlQBzabdorQ',
        'base64url',
    );

    // Assertion response
    const assertionResponse = {
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
        id: 'qD4q4HgXghVQsQ-nZ4hUQA',
        rawId: 'qD4q4HgXghVQsQ-nZ4hUQA',
        response: {
            authenticatorData:
                '4TC-5A7KzTOua9YfDGFAUMF9-b3-qr9dNVgPV1NVCzwdAAAAAA',
            clientDataJSON:
                'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYzNSeWFXNW5ZMmhoYkd4bGJtZGwiLCJvcmlnaW4iOiJhbmRyb2lkOmFway1rZXktaGFzaDpmQzR5YW1HMFZrRmdwVXFPT0RsdlBLaEtRRXp5aklrLWtKemMwQlRZa3VZIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiZXhwby5tb2R1bGVzLmV4cG9jbGF2ZXBhc3NrZXkuZXhhbXBsZSJ9',
            signature:
                'MEUCIQDJEoRVqk2FsqBz07shFIbveeSds8G9FLgGrIV0-BY7uAIgZasRb6LOe4hhYnrs1NlyZISP6id6cpigXEjcvFeVwA0',
            userHandle: 'dXNlcg',
        },
        type: 'public-key',
    };

    const { signature, clientDataJSON, authenticatorData } =
        assertionResponse.response;

    const obtainedClientDataJSON = JSON.parse(
        new TextDecoder().decode(Buffer.from(clientDataJSON, 'base64url')),
    );
    console.debug('clientDataJSON (parsed)', obtainedClientDataJSON, {
        ch: Buffer.from(obtainedClientDataJSON.challenge, 'base64url').toString(
            'hex',
        ),
    });

    const authenticatorDataAsUint8Array = new Uint8Array(
        Buffer.from(authenticatorData, 'base64url'),
    );
    const clientDataHash = new Uint8Array(
        await crypto.subtle.digest(
            'SHA-256',
            Buffer.from(clientDataJSON, 'base64url'),
        ),
    );

    // concat authenticatorData and clientDataHash
    const signedData = new Uint8Array(
        authenticatorDataAsUint8Array.length + clientDataHash.length,
    );
    signedData.set(authenticatorDataAsUint8Array);
    signedData.set(clientDataHash, authenticatorDataAsUint8Array.length);

    const key = await importPublicKeyAsCryptoKey(publicKey);
    if (!key) {
        console.error('Failed to import public key');
        return;
    }

    // Convert signature from ASN.1 sequence to "raw" format
    const usignature = new Uint8Array(Buffer.from(signature, 'base64url'));
    const rStart = usignature[4] === 0 ? 5 : 4;
    const rEnd = rStart + 32;
    const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
    const r = usignature.slice(rStart, rEnd);
    const s = usignature.slice(sStart);
    const rawSignature = new Uint8Array([...r, ...s]);

    const verified = await crypto.subtle.verify(
        <EcdsaParams>{
            name: 'ECDSA',
            namedCurve: 'P-256',
            hash: { name: 'SHA-256' },
        },
        key as CryptoKey,
        rawSignature,
        signedData,
    );

    const pubKey = Buffer.from(publicKey.toString('hex').substring(54), 'hex');
    const x = pubKey.subarray(0, 32);
    const y = pubKey.subarray(32);

    const encoded = new Uint8Array(
        await crypto.subtle.digest('SHA-256', signedData),
    );

    console.log({
        isValid: verified,
        signature: rawSignature,
        data: signedData,
        x,
        y,
        r,
        s,
        clientDataHash: encoded,
    });
}

main().catch(console.error);
