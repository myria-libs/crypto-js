import { SignatureOptions, ISignature, ValidationResult } from "./types";
/**
 * Serialize the SignatureOptions to string
 *
 * @param {SignatureOptions} sig - The signature output from signing.
 *  @returns {string} The serialized result as string
 */
export declare function serializeSignatureOptions(sig: SignatureOptions): string;
/**
 * Deserialize serialized signature from string to SignatureOptions object
 *
 * @param {string} sig - The serialized signature in string format.
 *  @returns {SignatureOptions} The SignatureOptions object with r & s in BN format
 */
export declare function deserializeSignature(sig: string, size?: number): SignatureOptions;
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
export declare function generateHeaderSignatureFromTimestamp(myriaPrivateStarkKey: string, starkKey: string, timestamp: number, url?: string, payloadSerialization?: string, shouldLogMessageHash?: boolean): ISignature;
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
export declare function validateHeaderSignature(signature: string, starkKey: string, timestamp: number, expirationInSeconds?: number, url?: string, payloadSerialization?: string, shouldLogMessageHash?: boolean): ValidationResult;
