import test from 'node:test';
import assert from 'node:assert/strict';
import { crc32, makeZip } from '../ui/js/zip.js';
import { makeQR } from '../ui/js/qr.js';

test('crc32 matches the standard check value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
});

test('makeZip writes a valid stored archive', async () => {
  const blob = makeZip([{ name: 'redx.toml', text: 'listen = "x"\n' }, { name: 'README.txt', text: 'hi' }]);
  const buf = new Uint8Array(await blob.arrayBuffer());
  const dv = new DataView(buf.buffer);
  assert.equal(dv.getUint32(0, true), 0x04034b50, 'local header signature');
  // end of central directory record
  const eocd = buf.length - 22;
  assert.equal(dv.getUint32(eocd, true), 0x06054b50);
  assert.equal(dv.getUint16(eocd + 10, true), 2, 'two entries');
  const cdOff = dv.getUint32(eocd + 16, true);
  assert.equal(dv.getUint32(cdOff, true), 0x02014b50, 'central directory signature');
  const text = new TextDecoder().decode(buf);
  assert.ok(text.includes('listen = "x"') && text.includes('README.txt'));
});

test('makeQR produces a square module grid with finder patterns', () => {
  const q = makeQR('RX-ABCDE-FGHJK');
  assert.equal(q.modules.length, q.size);
  assert.equal(q.size, 17 + 4 * q.version);
  assert.ok(q.version >= 1 && q.version <= 3);
  for (const [r, c] of [[0, 0], [0, q.size - 7], [q.size - 7, 0]]) {
    for (let i = 0; i < 7; i++) {
      assert.ok(q.modules[r][c + i] && q.modules[r + 6][c + i], 'finder top/bottom edge');
      assert.ok(q.modules[r + i][c] && q.modules[r + i][c + 6], 'finder side edges');
    }
    assert.ok(q.modules[r + 3][c + 3], 'finder centre');
    assert.ok(!q.modules[r + 1][c + 1], 'finder inner ring is light');
  }
  const long = makeQR('https://192.168.1.20:7777/#/join?c=RX-ABCDE-FGHJK&pin=' + 'a'.repeat(64));
  assert.ok(long.version > q.version);
  assert.throws(() => makeQR('x'.repeat(5000)));
});
