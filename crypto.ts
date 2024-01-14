import {
    base64_variants,
    crypto_box_easy, crypto_box_keypair, crypto_box_NONCEBYTES,
    crypto_box_open_easy,
    crypto_box_seal,
    crypto_box_seal_open, crypto_generichash, crypto_generichash_BYTES, crypto_secretbox_easy,
    crypto_secretbox_keygen, crypto_secretbox_open_easy,
    crypto_sign_detached,
    crypto_sign_keypair,
    crypto_sign_verify_detached,
    from_base64,
    KeyType,
    randombytes_buf,
    ready,
    to_base64
} from "libsodium-wrappers";

// API docs at https://doc.libsodium.org/



type UnusedGenericsHack<_T> = never; // TODO: for some reason in the upgrade from TS4 to 5, this code is broken when referenced from another file - it seemed like the compiler is optimising out _T as it's unused, but this code does use it!
export type Signature<_T> = (Uint8Array & { readonly __tag_Signature: unique symbol }) | UnusedGenericsHack<_T>;
export type Hash<_T> = (Uint8Array & { readonly __tag_Hash: unique symbol }) | UnusedGenericsHack<_T>;
export type SealedData<_T> = (Uint8Array & { readonly __tag_SealedData: unique symbol }) | UnusedGenericsHack<_T>;
export type Base64<_T> = (string & { readonly __tag_Base64String: unique symbol }) | UnusedGenericsHack<_T>;
export type RandomBytes = Uint8Array & { readonly __tag_RandomBytes: unique symbol };
export type Nonce = RandomBytes & { readonly __tag_Nonce: unique symbol };


export async function base64<T extends Uint8Array>(input: Base64<T>, variant?: base64_variants): Promise<T>;
export async function base64<T extends Uint8Array>(input: T, variant?: base64_variants): Promise<Base64<T>>;
export async function base64<T extends Uint8Array>(input: T | Base64<T>, variant: base64_variants = base64_variants.ORIGINAL): Promise<T | Base64<T>> {
    await ready;
    return typeof input === 'string'
        ? from_base64(input, variant) as T
        : to_base64(input, variant) as Base64<T>;
}

export async function randomBytesBuf(length: number): Promise<RandomBytes> {
    await ready;
    return randombytes_buf(length, "uint8array") as RandomBytes;
}

export async function generateNonce(): Promise<Nonce> {
    return await randomBytesBuf(crypto_box_NONCEBYTES) as Nonce;
}

/******************************************************************************
 * Hashing
 * Algorithm: BLAKE2b
 *****************************************************************************/

export async function cryptoGenericHash<T extends Uint8Array>(message: T, hashLength = crypto_generichash_BYTES, key?: RandomBytes): Promise<Hash<T>> {
    await ready;
    return await crypto_generichash(hashLength, message, key, "uint8array") as Hash<T>;
}

/******************************************************************************
 * Signing
 * Single-part signature: Ed25519
 * Multi-part signature: Ed25519ph
 *****************************************************************************/

export type PublicSignKey = Uint8Array & { readonly __tag_PublicSignKey: unique symbol };
export type PrivateSignKey = Uint8Array & { readonly __tag_PrivateSignKey: unique symbol };

export type SignKeyPair = {
    keyType: KeyType,
    privateKey: PrivateSignKey,
    publicKey: PublicSignKey,
};

export async function generateSignKeypair(): Promise<SignKeyPair> {
    await ready;
    return crypto_sign_keypair("uint8array") as SignKeyPair;
}

export async function cryptoSignDetached<T extends Uint8Array>(message: T, privateKey: PrivateSignKey): Promise<Signature<T>> {
    await ready;
    return crypto_sign_detached(message, privateKey, "uint8array") as Signature<T>;
}

export async function cryptoSignVerifyDetached<T extends Uint8Array>(signature: Signature<T>, message: Uint8Array, publicKey: PublicSignKey): Promise<boolean> {
    await ready;
    return crypto_sign_verify_detached(signature, message, publicKey);
}

/******************************************************************************
 * Crypto box is for authenticated public key crypto
 * - Both sides have keypairs
 * - It's slow (?)
 * - Do care who the message came from
 *
 * Key exchange: X25519
 * Encryption: XSalsa20
 * Authentication: Poly1305
 *****************************************************************************/
export type BoxPublicKey = Uint8Array & { readonly __tag_BoxPublicKey: unique symbol };
export type RecipientBoxPublicKey = BoxPublicKey;
export type SenderBoxPublicKey = BoxPublicKey;
export type BoxPrivateKey = Uint8Array & { readonly __tag_BoxPrivateKey: unique symbol };
export type SenderBoxPrivateKey = BoxPrivateKey;
export type RecipientBoxPrivateKey = BoxPrivateKey;

export type BoxKeyPair = {
    keyType: KeyType,
    privateKey: BoxPrivateKey,
    publicKey: BoxPublicKey,
};

export type CryptoBoxData<_T> = Uint8Array & { readonly __tag_CryptoBoxData: unique symbol };

export async function cryptoBoxKeyPair(): Promise<BoxKeyPair> {
    await ready;
    return crypto_box_keypair("uint8array") as BoxKeyPair;
}

export async function cryptoBoxEasy<T extends Uint8Array>(message: T, nonce: Nonce, recipientPublicKey: RecipientBoxPublicKey, senderPrivateKey: SenderBoxPrivateKey): Promise<CryptoBoxData<T>> {
    await ready;
    return crypto_box_easy(message, nonce, recipientPublicKey, senderPrivateKey, "uint8array") as CryptoBoxData<T>;
}

export async function cryptoBoxOpenEasy<T extends Uint8Array>(message: CryptoBoxData<T>, nonce: Nonce, senderPublicKey: SenderBoxPublicKey, recipientPrivateKey: RecipientBoxPrivateKey): Promise<T> {
    await ready;
    return crypto_box_open_easy(message, nonce, senderPublicKey, recipientPrivateKey, "uint8array") as T;
}


/******************************************************************************
 * Sealed box is for public key crypto
 * - Both sides have keypairs
 * - Don't care who the message came from
 *
 * Same implementation as Crypto Box:
 * Key exchange: X25519
 * Encryption: XSalsa20
 * Authentication: Poly1305
 *****************************************************************************/

export async function cryptoBoxSeal<T extends Uint8Array>(message: T, recipientPublicKey: RecipientBoxPublicKey): Promise<SealedData<T>> {
    await ready;
    return crypto_box_seal(message, recipientPublicKey, "uint8array") as SealedData<T>;
}

export async function cryptoBoxSealOpen<T extends Uint8Array>(message: SealedData<T>, recipientPublicKey: RecipientBoxPublicKey, privateKey: RecipientBoxPrivateKey): Promise<T> {
    await ready;
    return crypto_box_seal_open(message, recipientPublicKey, privateKey, "uint8array") as T;
}


/******************************************************************************
 * Secret key crypto
 * - Fast
 *
 * Encryption: XSalsa20 stream cipher
 * Authentication: Poly1305 MAC
 *****************************************************************************/

export type SecretBoxKey = Uint8Array & { readonly __tag_SecretBoxKey: unique symbol };
export type SecretBoxData<_T> = Uint8Array & { readonly __tag_SecretBoxData: unique symbol };

export async function cryptoSecretBoxKeygen(): Promise<SecretBoxKey> {
    await ready;
    return crypto_secretbox_keygen() as SecretBoxKey;
}

export async function cryptoSecretBoxEasy<T extends Uint8Array>(message: T, nonce: Nonce, key: SecretBoxKey): Promise<SecretBoxData<T>> {
    await ready;
    return crypto_secretbox_easy(message, nonce, key, "uint8array") as SecretBoxData<T>;
}

export async function cryptoSecretBoxOpenEasy<T extends Uint8Array>(message: SecretBoxData<T>, nonce: Nonce, key: SecretBoxKey): Promise<T> {
    await ready;
    return crypto_secretbox_open_easy(message, nonce, key, "uint8array") as T;
}
