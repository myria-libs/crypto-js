import BN from "bn.js";
import * as encUtils from "enc-utils";
import md5 from "md5";
import * as starkwareCrypto from "@starkware-industries/starkware-crypto-utils";

// Internal imports
import { SignatureOptions, ISignature, ValidationResult } from "./types";

// Internal functions
function isValid(
    publicKey: string,
    msgHash: BN,
    r: BN,
    s: BN,
    prefix: string,
): boolean {
    const pubKey = encUtils.removeHexPrefix(addingEcPrefix(publicKey, prefix));

    const result: boolean = starkwareCrypto.verify(
        starkwareCrypto.ec.keyFromPublic(pubKey, "hex"),
        msgHash.toString(16),
        {
            r,
            s,
        },
    );
    return result;
}

function addingEcPrefix(input: string, prefix: string): string {
    let key = input;
    key = encUtils.removeHexPrefix(key);

    if (key.length > 64) {
        return key;
    }

    while (key.length < 66) {
        key = `0${key}`;
    }
    key = `${prefix}${key.substring(2)}`;
    return key;
}

function isSignatureValid(
    signature: SignatureOptions,
    msgHash: BN,
    publicKey: string,
): boolean {
    try {
        let result: boolean = isValid(
            publicKey,
            msgHash,
            signature.r,
            signature.s,
            "0x02",
        );

        if (result) {
            return true;
        }

        result = isValid(publicKey, msgHash, signature.r, signature.s, "0x03");

        return result;
    } catch (err) {
        return false;
    }
}

function generateHeaderMsgHash(
    timestamp: number,
    url?: string,
    payloadSerialization?: string,
): BN {
    const rawMessageToHash = url ?? "" + payloadSerialization ?? "";
    const pedersen = starkwareCrypto.pedersen;
    return pedersen([
        pedersen([timestamp.toString(), md5(rawMessageToHash)]),
        "header:",
    ]);
}

// Public functions to let client consume

/**
 * Serialize the SignatureOptions to string
 *
 * @param {SignatureOptions} sig - The signature output from signing.
 *  @returns {string} The serialized result as string
 */
export function serializeSignatureOptions(sig: SignatureOptions): string {
    return encUtils.addHexPrefix(
        encUtils.padLeft(sig.r.toString(16), 64) +
            encUtils.padLeft(sig.s.toString(16), 64),
    );
}

/**
 * Deserialize serialized signature from string to SignatureOptions object
 *
 * @param {string} sig - The serialized signature in string format.
 *  @returns {SignatureOptions} The SignatureOptions object with r & s in BN format
 */
export function deserializeSignature(sig: string, size = 64): SignatureOptions {
    sig = encUtils.removeHexPrefix(sig);
    return {
        r: new BN(sig.substring(0, size), "hex"),
        s: new BN(sig.substring(size, size * 2), "hex"),
    };
}

/**
 * Client generates signature header for a request
 *
 * @param {string} myriaPrivateStarkKey - Myria Private Stark Key return when registering wallet
 * @param {string} starkKey - Myria Public Stark Key return when registering wallet
 * @param {number} timestamp - The timestamp use to sign from client in milliseconds format
 * @param {string?} url - The optional url is gonna be invoke e.g. /api/v1/users/1
 * @param {string?} payloadSerialization - The optional payloadSerialization is gonna be sent along with the request
 * @param {boolean?} shouldLogMessageHash - Whether to log the messageHash when verifier regenerate from request's input
 *  @returns {ISignature} The ISignature object to send in the request's header later on
 * @example
 * ```js
 * import { Signature } from '@myria/crypto-js';
 *
 * const headerSignature = Signature.generateHeaderSignatureFromTimestamp(
 *   myriaPrivateStarkKey,
 *   starkKey,
 *   timestamp,
 *   url,
 *   payloadSerialization
 * );
 * ```
 */
export function generateHeaderSignatureFromTimestamp(
    myriaPrivateStarkKey: string,
    starkKey: string,
    timestamp: number,
    url?: string,
    payloadSerialization?: string,
    shouldLogMessageHash = true,
): ISignature {
    if (!myriaPrivateStarkKey) {
        throw new Error("Myria Private Stark Key is required");
    }
    if (!starkKey) {
        throw new Error("Myria stark key is required");
    }
    if (!timestamp) {
        throw new Error("Timestamp with seconds is required");
    }
    if (new Date(timestamp) > new Date()) {
        throw new Error(
            "Invalid timestamp. Timestamp in the future is not allowed.",
        );
    }
    const signer = starkwareCrypto.ec.keyFromPrivate(
        myriaPrivateStarkKey,
        "hex",
    );
    const msgHash = generateHeaderMsgHash(timestamp, url, payloadSerialization);
    if (shouldLogMessageHash) {
        console.log(`[crypto-js] Client generates msgHash = ${msgHash}`);
    }

    const signature = <SignatureOptions>(
        starkwareCrypto.sign(signer, msgHash.toString())
    );

    return {
        "x-signature": serializeSignatureOptions(signature),
        "x-timestamp": timestamp,
        "stark-key": starkKey,
    };
}

/**
 * Verify Client's signature in request's header
 *
 * @param {string} signature - The serialized signature in string format
 * @param {string} starkKey - Myria Public Stark Key return when registering wallet
 * @param {number} timestamp - The timestamp use to sign from client in milliseconds format
 * @param {number?} expirationInSeconds - The duration for a request to be considered expired
 * @param {string?} url - The optional url is gonna be invoke e.g. /api/v1/users/1
 * @param {string?} payloadSerialization - The optional payloadSerialization is gonna be sent along with the request
 * @param {boolean?} shouldLogMessageHash - Whether to log the messageHash when verifier regenerate from request's input
 *  @returns {ValidationResult} The ValidationResult whether VALID | INVALID | EXPIRED
 * @example
 * ```js
 * import { Signature } from '@myria/crypto-js';
 *
 * const headerSignature = Signature.validateHeaderSignature(
 *   signature,
 *   starkKey,
 *   timestamp,
 *   expireInSeconds,
 *   url,
 *   payloadSerialization
 * );
 * ```
 */
export function validateHeaderSignature(
    signature: {
        headerSignature: string;
        starkKey: string;
        timestamp: number;
        url?: string;
        payloadSerialization?: string;
    },
    expirationInSeconds?: number,
    shouldLogMessageHash = true,
): ValidationResult {
    const msgHash = generateHeaderMsgHash(
        signature.timestamp,
        signature.url,
        signature.payloadSerialization,
    );
    if (shouldLogMessageHash) {
        console.log(`[crypto-js] Verifier regenerates msgHash = ${msgHash}`);
    }
    const signatureOptions = deserializeSignature(signature.headerSignature);
    const isValid = isSignatureValid(
        signatureOptions,
        msgHash,
        signature.starkKey,
    );
    if (isValid) {
        if (expirationInSeconds) {
            const expiredDate = new Date(
                signature.timestamp + expirationInSeconds * 1000,
            );
            if (expiredDate <= new Date()) {
                return ValidationResult.EXPIRED;
            }
        }
        return ValidationResult.VALID;
    }
    return ValidationResult.INVALID;
}
