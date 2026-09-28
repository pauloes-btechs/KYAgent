// In-process event hub feeding GET /v1/events/stream (openapi `streamEvents`, types.ts
// HarnessStreamEvent). Publishers: the sanctions watcher, the investigation routes. Delivery is
// best effort and in-process only; the authoritative record is Atlas (passports, investigations,
// audit_events). A throwing subscriber never affects the publisher or other subscribers.

/** Contract stream events (types.ts HarnessStreamEvent). */
export const HARNESS_STREAM_EVENTS = Object.freeze(['sanctions.change_detected', 'passport.status_changed', 'investigation.decided', 'harness.adapted']);
/** Demo 4 "Continuous KYA" progress steps (DELIVERY_PLAN T11/T16), emitted alongside the contract events. */
export const DEMO4_STREAM_EVENTS = Object.freeze(['change_detected', 'affected_agent', 'rescreen_started', 'passport_suspended']);
export const STREAM_EVENT_TYPES = Object.freeze([...HARNESS_STREAM_EVENTS, ...DEMO4_STREAM_EVENTS]);

export function createEventHub({ clock = { now: () => new Date() } } = {}) {
  const subscribers = new Set();
  return {
    /** Subscribe `fn({ type, data })`; returns the unsubscribe function. */
    subscribe(fn) {
      subscribers.add(fn);
      return () => subscribers.delete(fn);
    },
    /** Publish one event. `data.at` defaults to now (ISO). Unknown types are a programming error. */
    publish(type, data = {}) {
      if (!STREAM_EVENT_TYPES.includes(type)) throw new Error(`unknown stream event type ${type}`);
      const event = { type, data: { type, at: clock.now().toISOString(), ...data } };
      for (const fn of subscribers) {
        try {
          fn(event);
        } catch {
          // a broken subscriber (closed socket) must not affect the others
        }
      }
    },
    get size() {
      return subscribers.size;
    },
  };
}
