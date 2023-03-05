export const bn2str = num => '0x' + num.toBuffer('be', 32).toString('hex');
export const timeout = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
