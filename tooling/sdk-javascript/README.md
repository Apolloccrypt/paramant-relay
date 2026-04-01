# @paramant/connect — JavaScript / TypeScript
```bash
npm install @paramant/connect
```

## Vereisten
- Node.js >= 18
- Browser met WebCrypto API (alle moderne browsers)

## Gebruik
```javascript
import { GhostPipe } from '@paramant/connect';

const gp = new GhostPipe('pgp_xxx', 'device-001', {
  relay: 'https://health.paramant.app'
});

// Sturen
const hash = await gp.send(buffer);          // Buffer of Uint8Array
const hash = await gp.sendFile(file);        // File object (browser)

// Ontvangen
const data = await gp.receive(hash);         // returns Uint8Array

// Continu luisteren (WebSocket)
gp.listen((data) => {
  console.log('ontvangen:', data.byteLength, 'bytes');
});
```

## CommonJS
```javascript
const { GhostPipe } = require('@paramant/connect');
```

## Browser (CDN)
```html
<script type="module">
  import { GhostPipe } from 'https://unpkg.com/@paramant/connect/dist/index.esm.js';
</script>
```

## Publiceren (npm)
```bash
npm login
npm publish --access public
```

Package: [npmjs.com/package/@paramant/connect](https://www.npmjs.com/package/@paramant/connect)
