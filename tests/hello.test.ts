import { hello } from '../src';

test('adds two numbers correctly', () => {
    const result = hello('myria');
    expect(result).toBe('Hello myria. Have a great day!');
});
