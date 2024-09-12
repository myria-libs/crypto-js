import BN from "bn.js";
import * as encUtils from "enc-utils";
import { ISignature } from "./types/signature.interface";

/* eslint-disable */
const StarkwareLib = require("@starkware-industries/starkware-crypto-utils");

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
    return StarkwareLib.pedersen([timestamp, "header:"]);
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
    const signer = StarkwareLib.ec.keyFromPrivate(myriaPrivateStarkKey, "hex");
    const msgHash = generateHeaderMsgHash(timestamp.toString());
    const signature = <SignatureOptions>StarkwareLib.sign(signer, msgHash);

    return {
        "x-signature": serializeSignatureOptions(signature),
        "x-timestamp": timestamp.toString(),
        "stark-key": starkKey,
    };
}
