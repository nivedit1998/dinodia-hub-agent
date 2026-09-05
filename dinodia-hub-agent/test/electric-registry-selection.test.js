const test = require('node:test');
const assert = require('node:assert/strict');
const { stateClass } = require('../electricUsageTracker');

test('registry selection accepts Light labels inherited from a device and ignores diagnostics', () => {
  const labelNameById = new Map([['label-light', 'Light'], ['label-radiator', 'Radiator']]);
  const device = { labels: ['label-light'] };
  const eligible = (row) => {
    if (!/^(light|switch)\./i.test(row.entity_id) || row.disabled_by || row.hidden_by) return false;
    const names = [...(row.labels || []), ...(device.labels || [])].map((id) => labelNameById.get(id) || '');
    return names.some((name) => name.toLowerCase() === 'light');
  };
  assert.equal(eligible({ entity_id: 'switch.two_gang_1', labels: [] }), true);
  assert.equal(eligible({ entity_id: 'sensor.two_gang_voltage', labels: [] }), false);
  assert.equal(eligible({ entity_id: 'light.disabled', labels: [], disabled_by: 'user' }), false);
  assert.deepEqual(stateClass('on'), { known: true, isOn: true });
  assert.deepEqual(stateClass('unknown'), { known: false, isOn: false });
});
