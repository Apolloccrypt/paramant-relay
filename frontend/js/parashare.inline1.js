
import { initCrypto, encryptBlob as _eb } from './crypto-bridge.js?v=4';
window._cryptoBridge = { encryptBlob: _eb };
initCrypto().catch(e => console.error('WASM init failed:', e));
