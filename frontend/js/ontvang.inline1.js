
import { initCrypto, encryptBlob, decryptBlob } from '/crypto-bridge.js?v=4';
window._cryptoBridge = { initCrypto, encryptBlob, decryptBlob };
// Pre-warm WASM (integrity check + init) so it's ready when a transfer arrives
initCrypto().catch(e => console.error('WASM init failed:', e));
