/** Which kind of signable image a byte string is, decided from its magic number alone. */
import { isCompoundFile } from './cfb.ts';

export type ImageKind = 'pe' | 'msi';

export class ImageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ImageError';
  }
}

export function detectImageKind(bytes: Uint8Array): ImageKind {
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return 'pe';
  if (isCompoundFile(bytes)) return 'msi';
  throw new ImageError('not a signable file: neither a PE image (MZ) nor an MSI package (OLE compound file)');
}
