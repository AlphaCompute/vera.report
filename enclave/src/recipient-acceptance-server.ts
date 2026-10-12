/** Only the explicit recipient-acceptance image launches this service. */
import { nativeAttest } from './channel-server.js';
import { createRecipientChannelServer } from './recipient-channel.js';

createRecipientChannelServer(nativeAttest).then(server => {
  server.on('error', () => { process.exitCode = 1; server.close(); });
  server.listen(5003, '127.0.0.1');
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => server.close());
}).catch(() => {
  process.stderr.write('Recipient acceptance service startup failed\n');
  process.exitCode = 1;
});
