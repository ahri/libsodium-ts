/// <reference types="jest" />

import {
    base64,
    Base64,
    cryptoBoxEasy,
    cryptoBoxKeyPair,
    cryptoBoxOpenEasy,
    cryptoBoxSeal,
    cryptoBoxSealOpen,
    cryptoSecretBoxEasy,
    cryptoSecretBoxKeygen,
    cryptoSecretBoxOpenEasy,
    cryptoSignDetached,
    cryptoSignVerifyDetached, generateNonce,
    generateSignKeypair,
    randomBytesBuf
} from "./crypto";

const TE = new TextEncoder();
const TD = new TextDecoder();

export function utf8(x: Uint8Array): string;
export function utf8(x: string): Uint8Array;
export function utf8(x: string | Uint8Array): string | Uint8Array {
    return typeof x === "string"
        ? TE.encode(x)
        : TD.decode(x);
}

test("base64", async () => {
    const orig = "foo";
    const encoded: Base64<Uint8Array> = await base64(utf8(orig));
    const decoded = utf8(await base64(encoded));
    expect(decoded).toEqual(orig);
});

test("sign", async () => {
    const orig = "foo";
    const data = utf8(orig);
    const keys = await generateSignKeypair();
    const signature = await cryptoSignDetached(data, keys.privateKey);

    expect(await cryptoSignVerifyDetached(signature, data, keys.publicKey)).toBeTruthy();
    expect(await cryptoSignVerifyDetached(signature, utf8("other"), keys.publicKey)).toBeFalsy();
});

test("public key crypto", async () => {
    const aliceKeys = await cryptoBoxKeyPair();
    const bobKeys = await cryptoBoxKeyPair();

    const aliceToBobMsg = "alice";
    const aliceToBobData = utf8(aliceToBobMsg);
    const aliceToBobNonce = await generateNonce();
    const aliceToBobEncrypted = await cryptoBoxEasy(aliceToBobData, aliceToBobNonce, bobKeys.publicKey, aliceKeys.privateKey); // TODO: bundle the nonce?
    const aliceToBobDecrypted = await cryptoBoxOpenEasy(aliceToBobEncrypted, aliceToBobNonce, aliceKeys.publicKey, bobKeys.privateKey);

    expect(utf8(aliceToBobDecrypted)).toEqual(aliceToBobMsg);
});

test("sealed box", async () => {
    const bobKeys = await cryptoBoxKeyPair();

    const aliceToBobMsg = "alice";
    const aliceToBobData = utf8(aliceToBobMsg);
    const aliceToBobEncrypted = await cryptoBoxSeal(aliceToBobData, bobKeys.publicKey);
    const aliceToBobDecrypted = await cryptoBoxSealOpen(aliceToBobEncrypted, bobKeys.publicKey, bobKeys.privateKey);

    expect(utf8(aliceToBobDecrypted)).toEqual(aliceToBobMsg);
});

test("secret key crypto", async () => {
    const key = await cryptoSecretBoxKeygen();

    const msg = "foo";
    const data = utf8(msg);
    const nonce = await generateNonce();
    const encrypted = await cryptoSecretBoxEasy(data, nonce, key); // TODO: bundle the nonce?
    const decrypted = await cryptoSecretBoxOpenEasy(encrypted, nonce, key);

    expect(utf8(decrypted)).toEqual(msg);
});

test.skip("benchmarking", async () => {
    const symmetricKey = await cryptoSecretBoxKeygen();
    const asymmetricKeySender = await cryptoBoxKeyPair();
    const asymmetricKeyRecipient = await cryptoBoxKeyPair();

    const nonce = await generateNonce();
    const data = await randomBytesBuf(1024*256);
    const symmetricEncrypted = await cryptoSecretBoxEasy(data, nonce, symmetricKey);
    const asymmetricEncrypted = await cryptoBoxEasy(data, nonce, asymmetricKeyRecipient.publicKey, asymmetricKeySender.privateKey);
    const sealEncrypted = await cryptoBoxSeal(data, asymmetricKeyRecipient.publicKey);

    await benchmark("cryptoSecretBoxEasy", async () => {
        await cryptoSecretBoxEasy(data, nonce, symmetricKey);
    });

    await benchmark("cryptoSecretBoxOpenEasy", async () => {
        await cryptoSecretBoxOpenEasy(symmetricEncrypted, nonce, symmetricKey);
    });

    await benchmark("cryptoBoxEasy", async () => {
        await cryptoBoxEasy(data, nonce, asymmetricKeyRecipient.publicKey, asymmetricKeySender.privateKey);
    });

    await benchmark("cryptoBoxOpenEasy", async () => {
        await cryptoBoxOpenEasy(asymmetricEncrypted, nonce, asymmetricKeySender.publicKey, asymmetricKeyRecipient.privateKey);
    });

    await benchmark("cryptoBoxSeal", async () => {
        await cryptoBoxSeal(data, asymmetricKeyRecipient.publicKey);
    });

    await benchmark("cryptoBoxSealOpen", async () => {
        await cryptoBoxSealOpen(sealEncrypted, asymmetricKeyRecipient.publicKey, asymmetricKeyRecipient.privateKey);
    });
});

async function benchmark(title: string, f: () => Promise<void>) {
    const iterations = 10_000;

    // warm-up
    for (let i = 0; i < 10; i++) {
        await f();
    }

    const startMs = new Date().getTime();
    for (let i = 0; i < iterations; i++) {
        await f();
    }
    const endMs = new Date().getTime();

    console.log(`${title}: ${(endMs - startMs)/iterations}ms`);
}
