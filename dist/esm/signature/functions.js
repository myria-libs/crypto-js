import BN from "bn.js";
import * as encUtils from "enc-utils";
import md5 from "md5";
import * as starkwareCrypto from "@starkware-industries/starkware-crypto-utils";
// Internal imports
import { ValidationResult } from "./types";
// Internal functions
function isValid(publicKey, msgHash, r, s, prefix) {
    const pubKey = encUtils.removeHexPrefix(addingEcPrefix(publicKey, prefix));
    const result = starkwareCrypto.verify(starkwareCrypto.ec.keyFromPublic(pubKey, "hex"), msgHash.toString(16), {
        r,
        s,
    });
    return result;
}
function addingEcPrefix(input, prefix) {
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
function isSignatureValid(signature, msgHash, publicKey) {
    try {
        let result = isValid(publicKey, msgHash, signature.r, signature.s, "0x02");
        if (result) {
            return true;
        }
        result = isValid(publicKey, msgHash, signature.r, signature.s, "0x03");
        return result;
    }
    catch (err) {
        return false;
    }
}
function generateHeaderMsgHash(timestamp, url, payloadSerialization) {
    var _a;
    const rawMessageToHash = (_a = url !== null && url !== void 0 ? url : "" + payloadSerialization) !== null && _a !== void 0 ? _a : "";
    const pedersen = starkwareCrypto.pedersen;
    return pedersen([
        pedersen([
            timestamp.toString(),
            md5(rawMessageToHash),
        ]),
        "header:"
    ]);
}
// Public functions to let client consume
/**
 * Serialize the SignatureOptions to string
 *
 * @param {SignatureOptions} sig - The signature output from signing.
 *  @returns {string} The serialized result as string
 */
export function serializeSignatureOptions(sig) {
    return encUtils.addHexPrefix(encUtils.padLeft(sig.r.toString(16), 64) +
        encUtils.padLeft(sig.s.toString(16), 64));
}
/**
 * Deserialize serialized signature from string to SignatureOptions object
 *
 * @param {string} sig - The serialized signature in string format.
 *  @returns {SignatureOptions} The SignatureOptions object with r & s in BN format
 */
export function deserializeSignature(sig, size = 64) {
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
export function generateHeaderSignatureFromTimestamp(myriaPrivateStarkKey, starkKey, timestamp, url, payloadSerialization, shouldLogMessageHash = true) {
    if (!myriaPrivateStarkKey) {
        throw new Error("Myria Private Stark Key is required");
    }
    if (!starkKey) {
        throw new Error("Myria stark key is required");
    }
    if (!timestamp) {
        throw new Error("Timestamp with seconds is required");
    }
    const signer = starkwareCrypto.ec.keyFromPrivate(myriaPrivateStarkKey, "hex");
    const msgHash = generateHeaderMsgHash(timestamp, url, payloadSerialization);
    if (shouldLogMessageHash) {
        console.log(`[crypto-js] Client generates msgHash = ${msgHash}`);
    }
    const signature = (starkwareCrypto.sign(signer, msgHash.toString()));
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
export function validateHeaderSignature(signature, starkKey, timestamp, expirationInSeconds, url, payloadSerialization, shouldLogMessageHash = true) {
    const msgHash = generateHeaderMsgHash(timestamp, url, payloadSerialization);
    if (shouldLogMessageHash) {
        console.log(`[crypto-js] Verifier regenerates msgHash = ${msgHash}`);
    }
    const signatureOptions = deserializeSignature(signature);
    const isValid = isSignatureValid(signatureOptions, msgHash, starkKey);
    if (isValid) {
        if (expirationInSeconds) {
            const expiredDate = new Date(timestamp + expirationInSeconds * 1000);
            if (expiredDate <= new Date()) {
                return ValidationResult.EXPIRED;
            }
        }
        return ValidationResult.VALID;
    }
    return ValidationResult.INVALID;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZnVuY3Rpb25zLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL3NpZ25hdHVyZS9mdW5jdGlvbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLE1BQU0sT0FBTyxDQUFDO0FBQ3ZCLE9BQU8sS0FBSyxRQUFRLE1BQU0sV0FBVyxDQUFDO0FBQ3RDLE9BQU8sR0FBRyxNQUFNLEtBQUssQ0FBQztBQUN0QixPQUFPLEtBQUssZUFBZSxNQUFNLDhDQUE4QyxDQUFDO0FBRWhGLG1CQUFtQjtBQUNuQixPQUFPLEVBQWdDLGdCQUFnQixFQUFFLE1BQU0sU0FBUyxDQUFDO0FBRXpFLHFCQUFxQjtBQUNyQixTQUFTLE9BQU8sQ0FDWixTQUFpQixFQUNqQixPQUFXLEVBQ1gsQ0FBSyxFQUNMLENBQUssRUFDTCxNQUFjO0lBRWQsTUFBTSxNQUFNLEdBQUcsUUFBUSxDQUFDLGVBQWUsQ0FBQyxjQUFjLENBQUMsU0FBUyxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUM7SUFFM0UsTUFBTSxNQUFNLEdBQVksZUFBZSxDQUFDLE1BQU0sQ0FDMUMsZUFBZSxDQUFDLEVBQUUsQ0FBQyxhQUFhLENBQUMsTUFBTSxFQUFFLEtBQUssQ0FBQyxFQUMvQyxPQUFPLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxFQUNwQjtRQUNJLENBQUM7UUFDRCxDQUFDO0tBQ0osQ0FDSixDQUFDO0lBQ0YsT0FBTyxNQUFNLENBQUM7QUFDbEIsQ0FBQztBQUVELFNBQVMsY0FBYyxDQUFDLEtBQWEsRUFBRSxNQUFjO0lBQ2pELElBQUksR0FBRyxHQUFHLEtBQUssQ0FBQztJQUNoQixHQUFHLEdBQUcsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUVwQyxJQUFJLEdBQUcsQ0FBQyxNQUFNLEdBQUcsRUFBRSxFQUFFLENBQUM7UUFDbEIsT0FBTyxHQUFHLENBQUM7SUFDZixDQUFDO0lBRUQsT0FBTyxHQUFHLENBQUMsTUFBTSxHQUFH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