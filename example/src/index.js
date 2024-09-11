import 'dotenv/config';
import { add } from '@myria/npm-template-typescript';

function showResultSumOf(a, b) {
    return `@myria/npm-template-typescript: Sum of ${a} + ${b} = ${add(a, b)} `;
}