import url from "node:url";
const dirname = url.fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
export default {
  dirname
}

import HelperCrypto from './classes/helper/Crypto';

export {
  HelperCrypto
}