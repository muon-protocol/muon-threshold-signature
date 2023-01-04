
export const uuid = () => {
    return Date.now().toString(32) + Math.floor(Math.random()*999999999).toString(32);
}
