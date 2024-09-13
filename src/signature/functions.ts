import BN from "bn.js";
import * as encUtils from "enc-utils";
import { ISignature } from "./types/signature.interface";

import * as starkwareCrypto from "@starkware-industries/starkware-crypto-utils";
type SignatureOptions = {
    r: BN;
    s: BN;
};

export function serializeSignatureOptions(sig: SignatureOptions): string {
    return encUtils.addHexPrefix(
        encUtils.padLeft(sig.r.toString(16), 64) +
            encUtils.padLeft(sig.s.toString(16), 64),
    );
}

export function generateHeaderMsgHash(timestamp: string): BN {
    return starkwareCrypto.pedersen([timestamp, "header:"]);
}

export function generateHeaderSignatureFromTimestamp(
    myriaPrivateStarkKey: string,
    starkKey: string,
    timestamp: number,
): ISignature {
    if (!myriaPrivateStarkKey) {
        throw new Error("Myria Private Stark Key is required");
    }
    if (!starkKey) {
        throw new Error("Myria stark key is required");
    }
    if (!timestamp) {
        throw new Error("Timestampt with seconds is required");
    }
    const signer = starkwareCrypto.ec.keyFromPrivate(
        myriaPrivateStarkKey,
        "hex",
    );
    const msgHash = generateHeaderMsgHash(timestamp.toString());
    const signature = <SignatureOptions>(
        starkwareCrypto.sign(signer, msgHash.toString())
    );

    return {
        "x-signature": serializeSignatureOptions(signature),
        "x-timestamp": timestamp.toString(),
        "stark-key": starkKey,
    };
}

export function isValidHeaderSignature(
    signature: string,
    starkKey: string,
    timestamp: string,
    expirationInSeconds?: number,
): boolean {
    const msgHash = generateHeaderMsgHash(timestamp);
    const signatureOptions = deserializeSignature(signature);
    const isValid = isSignatureValid(signatureOptions, msgHash, starkKey);
    if (isValid) {
        if (expirationInSeconds) {
            const timeStampDate = new Date(timestamp);
            const expiredDate = new Date(
                timeStampDate.getTime() + expirationInSeconds * 1000,
            );
            if (expiredDate <= new Date()) {
                return false;
            }
        }
        return true;
    }
    return false;
}

function deserializeSignature(sig: string, size = 64): SignatureOptions {
    sig = encUtils.removeHexPrefix(sig);
    return {
        r: new BN(sig.substring(0, size), "hex"),
        s: new BN(sig.substring(size, size * 2), "hex"),
    };
}

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
