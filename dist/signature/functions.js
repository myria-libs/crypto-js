"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateHeaderSignature = exports.generateHeaderSignatureFromTimestamp = exports.deserializeSignature = exports.serializeSignatureOptions = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
const encUtils = __importStar(require("enc-utils"));
const md5_1 = __importDefault(require("md5"));
const starkwareCrypto = __importStar(require("@starkware-industries/starkware-crypto-utils"));
// Internal imports
const types_1 = require("./types");
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
            (0, md5_1.default)(rawMessageToHash),
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
function serializeSignatureOptions(sig) {
    return encUtils.addHexPrefix(encUtils.padLeft(sig.r.toString(16), 64) +
        encUtils.padLeft(sig.s.toString(16), 64));
}
exports.serializeSignatureOptions = serializeSignatureOptions;
/**
 * Deserialize serialized signature from string to SignatureOptions object
 *
 * @param {string} sig - The serialized signature in string format.
 *  @returns {SignatureOptions} The SignatureOptions object with r & s in BN format
 */
function deserializeSignature(sig, size = 64) {
    sig = encUtils.removeHexPrefix(sig);
    return {
        r: new bn_js_1.default(sig.substring(0, size), "hex"),
        s: new bn_js_1.default(sig.substring(size, size * 2), "hex"),
    };
}
exports.deserializeSignature = deserializeSignature;
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
function generateHeaderSignatureFromTimestamp(myriaPrivateStarkKey, starkKey, timestamp, url, payloadSerialization, shouldLogMessageHash = true) {
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
exports.generateHeaderSignatureFromTimestamp = generateHeaderSignatureFromTimestamp;
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
function validateHeaderSignature(signature, starkKey, timestamp, expirationInSeconds, url, payloadSerialization, shouldLogMessageHash = true) {
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
                return types_1.ValidationResult.EXPIRED;
            }
        }
        return types_1.ValidationResult.VALID;
    }
    return types_1.ValidationResult.INVALID;
}
exports.validateHeaderSignature = validateHeaderSignature;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZnVuY3Rpb25zLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3NpZ25hdHVyZS9mdW5jdGlvbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxrREFBdUI7QUFDdkIsb0RBQXNDO0FBQ3RDLDhDQUFzQjtBQUN0Qiw4RkFBZ0Y7QUFFaEYsbUJBQW1CO0FBQ25CLG1DQUF5RTtBQUV6RSxxQkFBcUI7QUFDckIsU0FBUyxPQUFPLENBQ1osU0FBaUIsRUFDakIsT0FBVyxFQUNYLENBQUssRUFDTCxDQUFLLEVBQ0wsTUFBYztJQUVkLE1BQU0sTUFBTSxHQUFHLFFBQVEsQ0FBQyxlQUFlLENBQUMsY0FBYyxDQUFDLFNBQVMsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDO0lBRTNFLE1BQU0sTUFBTSxHQUFZLGVBQWUsQ0FBQyxNQUFNLENBQzFDLGVBQWUsQ0FBQyxFQUFFLENBQUMsYUFBYSxDQUFDLE1BQU0sRUFBRSxLQUFLLENBQUMsRUFDL0MsT0FBTyxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsRUFDcEI7UUFDSSxDQUFDO1FBQ0QsQ0FBQztLQUNKLENBQ0osQ0FBQztJQUNGLE9BQU8sTUFBTSxDQUFDO0FBQ2xCLENBQUM7QUFFRCxTQUFTLGNBQWMsQ0FBQyxLQUFhLEVBQUUsTUFBYztJQUNqRCxJQUFJLEdBQUcsR0FBRyxLQUFLLENBQUM7SUFDaEIsR0FBRyxHQUFHLFFBQVEsQ0FBQyxlQUFlLENBQUMsR0FBRyxDQUFDLENBQUM7SUFFcEMsSUFBSSxHQUFHLENBQUMsTUFBTSxHQUFHLEVBQUUsRUFBRSxDQUFDO1FBQ2xCLE9BQU8sR0FBRyxDQUFDO0lBQ2YsQ0FBQztJQUVELE9BQU8sR0FBRyxDQUFDLE1BQU0sR0FBRyxFQUFFLEVBQUUsQ0FBQztRQUNyQixHQUFHLEdBQUcsSUFBSSxHQUFHLEVBQUUsQ0FBQztJQUNwQixDQUFDO0lBQ0QsR0FBRyxHQUFHLEdBQUcsTUFBTSxH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