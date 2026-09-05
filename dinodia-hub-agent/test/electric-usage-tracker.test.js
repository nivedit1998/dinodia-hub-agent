const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { ElectricUsageTracker, stateClass } = require('../electricUsageTracker');

test('Home Assistant electric tracker captures zero-origin runtime and rolls area history', () => {
  let now = new Date('2026-09-05T10:00:00.000Z');
  const tracker = new ElectricUsageTracker({ now: () => now, unknownGapAfterSeconds: 600 });
  const descriptor = (areaId, state) => ({ entityId: 'light.kitchen', entityName: 'Kitchen light', areaId, areaName: areaId === 'kitchen' ? 'Kitchen' : 'Hall', classification: stateClass(state) });
  tracker.observe(descriptor('kitchen', 'on'), now);
  now = new Date('2026-09-05T10:01:00.000Z');
  tracker.observe(descriptor('kitchen', 'on'), now);
  assert.equal(tracker.state.entities['light.kitchen'].onSeconds, 60);
  now = new Date('2026-09-05T10:02:00.000Z');
  tracker.observe(descriptor('hall', 'off'), now);
  const rows = tracker.payload().devices;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].areaName, 'Kitchen');
  assert.equal(rows[0].retired, true);
  assert.equal(rows[0].onSeconds, 120);
  assert.equal(rows[1].areaName, 'Hall');
});

test('Home Assistant electric tracker persists atomically and keeps failed uploads dirty', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dinodia-agent-electric-'));
  const persistPath = path.join(directory, 'electric.json');
  const tracker = new ElectricUsageTracker({ persistPath });
  tracker.observe({ entityId: 'switch.lamp', entityName: 'Lamp', areaId: null, areaName: null, classification: stateClass('off') });
  tracker.flush();
  const loaded = new ElectricUsageTracker({ persistPath });
  assert.equal(loaded.payload().devices[0].entityId, 'switch.lamp');
  assert.equal(loaded.payload().devices[0].lastWasKnown, true);
  const row = loaded.payload().devices[0];
  loaded.acknowledgeUploaded([]);
  assert.equal(loaded.payload().devices.length, 1);
  loaded.acknowledgeUploaded([row]);
  assert.equal(loaded.payload(), null);
});
