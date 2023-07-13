import numberToBN from  'number-to-bn'

export const uuid = () => {
    return Date.now().toString(32) + Math.floor(Math.random()*999999999).toString(32);
}

export function toBN(number) {
    try {
        return numberToBN.apply(null, arguments);
    }
    catch (e) {
        throw new Error(e + ' Given value: "' + number + '"');
    }
}
