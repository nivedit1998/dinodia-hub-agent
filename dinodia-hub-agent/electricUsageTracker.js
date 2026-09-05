const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const MAX_INTERVAL_SECONDS = 24 * 60 * 60;
const DEFAULT_UNKNOWN_GAP_SECONDS = 10 * 60;

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function isoDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function stateClass(value, available = true) {
  if (!available) return { known: false, isOn: false };
  const normalized = String(value ?? '').trim().toLowerCase();
  if (normalized === 'on') return { known: true, isOn: true };
  if (normalized === 'off') return { known: true, isOn: false };
  return { known: false, isOn: false };
}

class ElectricUsageTracker {
  constructor({ persistPath = '', maxTrackedEntities = 200, unknownGapAfterSeconds = DEFAULT_UNKNOWN_GAP_SECONDS, logger = console, now = () => new Date() } = {}) {
    this.persistPath = String(persistPath || '').trim();
    this.maxTrackedEntities = Math.max(1, Number(maxTrackedEntities) || 200);
    this.unknownGapAfterSeconds = Math.max(0, Number(unknownGapAfterSeconds) || DEFAULT_UNKNOWN_GAP_SECONDS);
    this.logger = logger;
    this.now = now;
    this.persistTimer = null;
    this.state = {
      schemaVersion: 1,
      updatedAt: null,
      lastResetAt: null,
      resetAckPendingAt: null,
      entities: {},
      pending: [],
    };
    this.load();
  }

  load() {
    if (!this.persistPath) return;
    try {
      const value = JSON.parse(fs.readFileSync(this.persistPath, 'utf8'));
      if (value?.schemaVersion !== 1) return;
      this.state = {
        schemaVersion: 1,
        updatedAt: value.updatedAt || null,
        lastResetAt: value.lastResetAt || null,
        resetAckPendingAt: value.resetAckPendingAt || null,
        entities: value.entities && typeof value.entities === 'object' ? value.entities : {},
        pending: Array.isArray(value.pending) ? value.pending : [],
      };
    } catch {
      // First install or a missing state file is normal.
    }
  }

  schedulePersist() {
    if (!this.persistPath || this.persistTimer) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null;
      const directory = path.dirname(this.persistPath);
      const temporary = `${this.persistPath}.tmp-${process.pid}-${Date.now()}`;
      try {
        fs.mkdirSync(directory, { recursive: true });
        this.state.updatedAt = new Date().toISOString();
        fs.writeFileSync(temporary, JSON.stringify(this.state, null, 2), { mode: 0o600 });
        fs.renameSync(temporary, this.persistPath);
      } catch (error) {
        try { fs.unlinkSync(temporary); } catch {}
        this.logger.warn(`[electric] Could not persist usage state: ${error.message}`);
      }
    }, 1000);
    this.persistTimer.unref?.();
  }

  flush() {
    if (this.persistTimer) clearTimeout(this.persistTimer);
    this.persistTimer = null;
    if (!this.persistPath) return;
    const directory = path.dirname(this.persistPath);
    const temporary = `${this.persistPath}.tmp-${process.pid}-${Date.now()}`;
    try {
      fs.mkdirSync(directory, { recursive: true });
      this.state.updatedAt = new Date().toISOString();
      fs.writeFileSync(temporary, JSON.stringify(this.state, null, 2), { mode: 0o600 });
      fs.renameSync(temporary, this.persistPath);
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch {}
      this.logger.warn(`[electric] Could not flush usage state: ${error.message}`);
    }
  }

  accrue(entry, observed) {
    const previous = isoDate(entry.lastSeenAt);
    const elapsed = previous ? Math.max(0, Math.min(MAX_INTERVAL_SECONDS, Math.floor((observed.getTime() - previous.getTime()) / 1000))) : 0;
    const unknown = elapsed > this.unknownGapAfterSeconds;
    if (entry.lastWasKnown === true && !unknown) {
      if (entry.lastWasOn === true) entry.onSeconds += elapsed;
      else entry.offSeconds += elapsed;
    } else {
      entry.unknownSeconds += elapsed;
    }
  }

  createEntry(descriptor, observed) {
    return {
      entityId: descriptor.entityId,
      entityName: descriptor.entityName || descriptor.entityId,
      trackingStartedAt: observed.toISOString(),
      trackingEpoch: crypto.randomUUID(),
      assignmentStartedAt: observed.toISOString(),
      assignmentEpoch: crypto.randomUUID(),
      areaId: descriptor.areaId || null,
      areaName: descriptor.areaName || null,
      onSeconds: 0,
      offSeconds: 0,
      unknownSeconds: 0,
      lastSeenAt: observed.toISOString(),
      lastWasOn: descriptor.classification?.isOn === true,
      lastWasKnown: descriptor.classification?.known === true,
      retired: false,
      dirty: true,
    };
  }

  observe(descriptor, observedAt = this.now()) {
    const observed = isoDate(observedAt);
    if (!observed || !descriptor?.entityId) return false;
    const state = this.state;
    let entry = state.entities[descriptor.entityId];
    if (!entry) {
      if (Object.keys(state.entities).length >= this.maxTrackedEntities) return false;
      state.entities[descriptor.entityId] = this.createEntry(descriptor, observed);
      this.schedulePersist();
      return true;
    }
    if (String(entry.areaId || '') !== String(descriptor.areaId || '') && !entry.retired) {
      this.accrue(entry, observed);
      state.pending.push({ ...clone(entry), retired: true, retiredAt: observed.toISOString(), dirty: true });
      entry = this.createEntry(descriptor, observed);
      state.entities[descriptor.entityId] = entry;
    } else {
      this.accrue(entry, observed);
    }
    Object.assign(entry, {
      entityName: descriptor.entityName || entry.entityName,
      areaId: descriptor.areaId || null,
      areaName: descriptor.areaName || null,
      lastSeenAt: observed.toISOString(),
      lastWasOn: descriptor.classification?.isOn === true,
      lastWasKnown: descriptor.classification?.known === true,
      retired: false,
      dirty: true,
    });
    this.schedulePersist();
    return true;
  }

  retire(entityId, observedAt = this.now()) {
    const observed = isoDate(observedAt);
    const entry = this.state.entities[String(entityId || '')];
    if (!observed || !entry || entry.retired) return false;
    this.accrue(entry, observed);
    entry.retired = true;
    entry.retiredAt = observed.toISOString();
    entry.dirty = true;
    this.schedulePersist();
    return true;
  }

  payload() {
    const rows = [
      ...this.state.pending.filter((entry) => entry?.dirty),
      ...Object.values(this.state.entities).filter((entry) => entry?.dirty),
    ];
    if (!rows.length) return null;
    return {
      schemaVersion: 1,
      capturedAt: new Date().toISOString(),
      devices: rows.map((entry) => ({
        label: 'Light',
        entityId: entry.entityId,
        entityName: entry.entityName || null,
        trackingStartedAt: entry.trackingStartedAt || null,
        trackingEpoch: entry.trackingEpoch,
        assignmentStartedAt: entry.assignmentStartedAt || null,
        assignmentEpoch: entry.assignmentEpoch,
        areaId: entry.areaId || null,
        areaName: entry.areaName || null,
        onSeconds: Math.max(0, Math.floor(Number(entry.onSeconds) || 0)),
        offSeconds: Math.max(0, Math.floor(Number(entry.offSeconds) || 0)),
        unknownSeconds: Math.max(0, Math.floor(Number(entry.unknownSeconds) || 0)),
        lastSeenAt: entry.lastSeenAt,
        lastWasOn: entry.lastWasOn === true,
        lastWasKnown: entry.lastWasKnown === true,
        retired: entry.retired === true,
      })),
    };
  }

  acknowledgeUploaded(rows = []) {
    const acknowledged = new Set(rows.map((row) => `${row.entityId || ''}|${row.trackingEpoch || ''}|${row.assignmentEpoch || ''}`));
    this.state.pending = this.state.pending.filter((entry) => !acknowledged.has(`${entry.entityId || ''}|${entry.trackingEpoch || ''}|${entry.assignmentEpoch || ''}`));
    for (const [entityId, entry] of Object.entries(this.state.entities)) {
      if (!acknowledged.has(`${entityId}|${entry.trackingEpoch || ''}|${entry.assignmentEpoch || ''}`)) continue;
      if (entry.retired) delete this.state.entities[entityId];
      else entry.dirty = false;
    }
    this.schedulePersist();
  }

  applyReset(resetAt) {
    const iso = isoDate(resetAt)?.toISOString();
    if (!iso || iso === this.state.lastResetAt) return;
    this.state = { schemaVersion: 1, updatedAt: null, lastResetAt: iso, resetAckPendingAt: iso, entities: {}, pending: [] };
    this.schedulePersist();
  }

  resetAcknowledgement() { return this.state.resetAckPendingAt || null; }

  acknowledgeReset(resetAt) {
    if (resetAt && this.state.resetAckPendingAt === resetAt) {
      this.state.resetAckPendingAt = null;
      this.schedulePersist();
    }
  }

  status() {
    return {
      enabled: true,
      trackedEntities: Object.keys(this.state.entities).length,
      pendingSegments: this.state.pending.length,
      dirtyEntities: Object.values(this.state.entities).filter((entry) => entry?.dirty).length + this.state.pending.filter((entry) => entry?.dirty).length,
      lastResetAt: this.state.lastResetAt || null,
    };
  }
}

module.exports = { ElectricUsageTracker, stateClass };
