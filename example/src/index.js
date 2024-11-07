import 'dotenv/config';
import { Signature } from '@myria/crypto-js';
const { ValidationResult } = Signature.Types;

function clientSignRequest(
    myriaPrivateStarkKey, 
    starkKey, 
    timestamp, 
    url = null, 
    payloadSerialization = null
) {
    return Signature.generateHeaderSignatureFromTimestamp(myriaPrivateStarkKey, starkKey, timestamp, url, payloadSerialization);
}

function verifyClientRequest(
    signature,
    starkKey,
    timestamp,
    expireInSeconds = null,
    url = null,
    payloadSerialization = null,
) {
    return Signature.validateHeaderSignature({headerSignature: signature, starkKey, timestamp, url, payloadSerialization}, expireInSeconds)
}

function waitInSeconds(delay) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve();
      }, delay*1000);
    });
}

async function simulateFullScenario(
    myriaPrivateStarkKey, 
    starkKey, 
    timestamp,
    url = null, 
    payloadSerialization = null,
    expectedValidationResult = ValidationResult.VALID
) {
    // 1. Client sign the request by their private key based on the rule. generic or customizing based on each endpoints
    const headerSignaturePayload = clientSignRequest(myriaPrivateStarkKey, starkKey, timestamp, url, payloadSerialization)
    console.log(`---> headerSignaturePayload = ${JSON.stringify(headerSignaturePayload)}`);
    
    // 2. BE verify the request. Sign the request with Client's public key and the signature contract
    let actualValidationResult = expectedValidationResult;
    switch (expectedValidationResult) {
        case ValidationResult.VALID:
            actualValidationResult = verifyClientRequest(
                headerSignaturePayload['x-signature'],
                headerSignaturePayload['stark-key'],
                headerSignaturePayload['x-timestamp'],
                3,
                url,
                payloadSerialization
            );
            break;
        case ValidationResult.INVALID:
            actualValidationResult = verifyClientRequest(
                headerSignaturePayload['x-signature'],
                headerSignaturePayload['stark-key'],
                headerSignaturePayload['x-timestamp'],
                3,
                url + '/abc',
                payloadSerialization
            );
            break;
        case ValidationResult.EXPIRED:
            await waitInSeconds(2);
            actualValidationResult = verifyClientRequest(
                headerSignaturePayload['x-signature'],
                headerSignaturePayload['stark-key'],
                headerSignaturePayload['x-timestamp'],
                1,
                url,
                payloadSerialization
            );
            break;
    }
    
    console.log('---> expectedValidationResult = ' + expectedValidationResult);
    console.log('---> actualValidationResult = ' + actualValidationResult);
}

// Input data as request's input
const URL = 'api/v1/submit-order';
const PAYLOAD_SERIALIZATION = JSON.stringify({userId: 1, amount: '100000000'});

console.log();
console.log('====1. Simulate VALID signature====');
simulateFullScenario(process.env.MYRIA_PRIVATE_KEY, process.env.MYRIA_PUBLIC_KEY,Date.now(),URL,PAYLOAD_SERIALIZATION);

console.log();
console.log('====2. Simulate INVALID signature====');
simulateFullScenario(process.env.MYRIA_PRIVATE_KEY, process.env.MYRIA_PUBLIC_KEY,Date.now(),URL,PAYLOAD_SERIALIZATION, ValidationResult.INVALID);

console.log();
console.log('====3. Simulate EXPIRED signature====');
simulateFullScenario(process.env.MYRIA_PRIVATE_KEY, process.env.MYRIA_PUBLIC_KEY,Date.now(),URL,PAYLOAD_SERIALIZATION, ValidationResult.EXPIRED);
