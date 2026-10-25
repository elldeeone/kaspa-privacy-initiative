// Official SDK clients retain their codecs; this owns a single local Tor session.
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline';

const DEFAULT_DEPS = '/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/python-deps';

export async function startTorBridge({upstream, proxyPort = 19050, deps = DEFAULT_DEPS} = {}) {
  const selected = new URL(upstream);
  if (selected.protocol !== 'wss:' || selected.username || selected.password || selected.search || selected.hash
      || !['/kaspa/testnet-10/wrpc/borsh', '/kaspa/testnet-10/wrpc/json'].includes(selected.pathname)
      || !Number.isSafeInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65535)
    throw new Error('explicit public TLS testnet peer and local SOCKS port required');
  const child = spawn('/usr/bin/python3', [fileURLToPath(new URL('./bridge.py', import.meta.url)),
    '--upstream', selected.href, '--proxy-port', String(proxyPort)], {
    env: {PATH: '/usr/bin:/bin', PYTHONPATH: deps}, stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Never forward process diagnostics or remote frame contents into wallet logs.
  child.stderr.resume();
  const lines = createInterface({input: child.stdout});
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    lines.close();
    if (child.exitCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM');
      await exited;
    }
  };
  try {
    const ready = await new Promise((resolve, reject) => {
      child.once('error', () => reject(new Error('local Tor bridge could not start')));
      child.once('exit', () => reject(new Error('local Tor bridge ended before ready')));
      lines.once('line', line => {
        try {
          const value = JSON.parse(line), endpoint = new URL(value.url);
          if (value.ready !== true || value.transport !== 'TOR_SOCKS5H_TLS' || value.sessions !== 1
              || endpoint.protocol !== 'ws:' || endpoint.hostname !== '127.0.0.1'
              || !endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash)
            throw new Error('invalid local bridge descriptor');
          resolve(value);
        } catch { reject(new Error('invalid local Tor bridge readiness')); }
      });
    });
    return {url: ready.url, transport: ready.transport, upstream: selected.href, close};
  } catch (error) {
    await close();
    throw error;
  }
}
