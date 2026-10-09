/**
 * Test Environment Setup for Node.js
 * Injects browser globals (localStorage, window mocks) so browser-first
 * modules can execute deterministically in Node.js test runner.
 */

if (typeof globalThis.localStorage === 'undefined') {
  const memoryStore: Record<string, string> = {};
  globalThis.localStorage = {
    getItem: (key: string) => memoryStore[key] ?? null,
    setItem: (key: string, value: string) => {
      memoryStore[key] = String(value);
    },
    removeItem: (key: string) => {
      delete memoryStore[key];
    },
    clear: () => {
      for (const k of Object.keys(memoryStore)) {
        delete memoryStore[k];
      }
    },
    key: (index: number) => Object.keys(memoryStore)[index] ?? null,
    length: 0,
  };
}

if (typeof globalThis.window === 'undefined') {
  (globalThis as any).window = {
    indexedDB: undefined,
    localStorage: globalThis.localStorage,
    crypto: globalThis.crypto,
  };
}
