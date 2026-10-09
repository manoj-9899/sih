import './setup.ts';
import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  serializeWatermarkPayload,
  deserializeWatermarkPayload,
  computeCrc16,
  embedWatermarkInText,
  extractWatermarkFromText,
} from '../src/watermark/engine.ts';
import { WatermarkPayload } from '../src/types';

describe('TEST GROUP 4: Forensic Watermarking & Steganography Engine', () => {
  const samplePayload: WatermarkPayload = {
    syncHeader: 0xa55a,
    sessionId: '12345678-1234-5678-1234-567812345678',
    watermarkId: 'WM-12345678',
    recipientId: 'USR-ALICE-01',
    recipientFingerprint: 'a1b2c3d4e5f67890',
    timestamp: 1790610000000,
    eccChecksum: 0,
  };

  it('4.1 Payload Serialization & Deserialization: roundtrips 32-byte binary payload', () => {
    const serialized = serializeWatermarkPayload(samplePayload);
    assert.strictEqual(serialized.length, 32, 'Serialized watermark payload must be 32 bytes');

    // Deserialization check
    const deserialized = deserializeWatermarkPayload(serialized, 'USR-ALICE-01');
    assert.ok(deserialized, 'Deserialization must succeed');
    assert.strictEqual(deserialized.syncHeader, 0xa55a, 'Sync header must be 0xA55A');
    assert.strictEqual(deserialized.watermarkId, samplePayload.watermarkId);
    assert.strictEqual(deserialized.recipientFingerprint, samplePayload.recipientFingerprint);
  });

  it('4.2 CRC-16 Integrity: detects byte corruption in serialized payload', () => {
    const serialized = serializeWatermarkPayload(samplePayload);
    const originalCrc = computeCrc16(serialized.slice(0, 30));

    // Corrupt one byte in the session ID area
    const corrupted = new Uint8Array(serialized);
    corrupted[6] ^= 0x01;

    const recalculateCrc = computeCrc16(corrupted.slice(0, 30));
    assert.notStrictEqual(recalculateCrc, originalCrc, 'Corrupting payload byte must alter CRC-16 checksum');
  });

  it('4.3 Text Embedding & Blind Extraction: recovers watermark from zero-width unicode', () => {
    const rawDocument = `Top Secret Memo\nThis directive governs infrastructure defense.\nAll copies are forensically tagged.`;
    const watermarkedText = embedWatermarkInText(rawDocument, samplePayload);

    // Visual appearance check: stripped of zero-width chars, length should equal original
    const stripped = watermarkedText.replace(/[\u200B\u200C\u200D\uFEFF]/g, '');
    assert.strictEqual(stripped, rawDocument, 'Stripping zero-width characters yields exact original text');

    // Blind extraction check: extract without original text reference
    const extracted = extractWatermarkFromText(watermarkedText);
    assert.ok(extracted, 'Blind extraction must successfully find zero-width bitstream');
    assert.strictEqual(extracted.watermarkId, samplePayload.watermarkId);
    assert.strictEqual(extracted.recipientFingerprint, samplePayload.recipientFingerprint);
  });

  it('4.4 Unique Session Watermarks: different recipients produce forensically distinct text', () => {
    const rawDocument = `Classified Transit Coordinates: North 14 deg, East 112 deg.`;

    const alicePayload: WatermarkPayload = {
      ...samplePayload,
      sessionId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      watermarkId: 'WM-AAAAAAAA',
      recipientId: 'USR-ALICE-01',
      recipientFingerprint: '1111111111111111',
    };

    const bobPayload: WatermarkPayload = {
      ...samplePayload,
      sessionId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
      watermarkId: 'WM-BBBBBBBB',
      recipientId: 'USR-BOB-02',
      recipientFingerprint: '2222222222222222',
    };

    const aliceText = embedWatermarkInText(rawDocument, alicePayload);
    const bobText = embedWatermarkInText(rawDocument, bobPayload);

    assert.notStrictEqual(aliceText, bobText, 'Watermarked strings must differ at the byte level');

    const recoveredAlice = extractWatermarkFromText(aliceText);
    const recoveredBob = extractWatermarkFromText(bobText);

    assert.strictEqual(recoveredAlice?.watermarkId, 'WM-AAAAAAAA');
    assert.strictEqual(recoveredBob?.watermarkId, 'WM-BBBBBBBB');
  });

  it('4.5 Corrupted Watermark Rejection: mutilated zero-width stream is rejected', () => {
    const unwatermarkedText = `Standard public memo with normal text and no steganography.`;
    const extracted = extractWatermarkFromText(unwatermarkedText);
    assert.strictEqual(extracted, null, 'Plain text must return null (zero false positives)');
  });
});
