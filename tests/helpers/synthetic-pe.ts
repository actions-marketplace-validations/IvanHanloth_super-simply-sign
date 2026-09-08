/**
 * Builds small but structurally valid PE32+ images for tests: a DOS stub,
 * COFF + optional headers with all 16 data directories, up to four sections
 * with 512-byte file alignment, and optional trailing (overlay) data.
 */
export interface SyntheticSection {
  readonly name: string;
  readonly data: Buffer;
}

export interface SyntheticPeOptions {
  /** List the section headers in reverse file order (the data stays in file order). */
  readonly reverseSectionTable?: boolean;
  readonly trailing?: Buffer;
  /** Override the security directory entry (offset, size). */
  readonly securityDirectory?: readonly [number, number];
}

const FILE_ALIGNMENT = 512;
const PE_OFFSET = 0x40;
const OPTIONAL_HEADER_SIZE = 240;
/** DOS header + PE signature + COFF header + PE32+ optional header. */
export const SECTION_TABLE_OFFSET = PE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE;
export const SYNTHETIC_HEADERS_SIZE = 512;

const align = (n: number, a: number): number => Math.ceil(n / a) * a;

export function buildSyntheticPe(sections: readonly SyntheticSection[], options: SyntheticPeOptions = {}): Buffer {
  if (sections.length > 4) throw new Error('at most four sections fit in the synthetic header');
  const headers = Buffer.alloc(SYNTHETIC_HEADERS_SIZE);
  headers.write('MZ', 0, 'latin1');
  headers.writeUInt32LE(PE_OFFSET, 0x3c);
  headers.write('PE\0\0', PE_OFFSET, 'latin1');
  const coff = PE_OFFSET + 4;
  headers.writeUInt16LE(0x8664, coff); // Machine: x64
  headers.writeUInt16LE(sections.length, coff + 2);
  headers.writeUInt16LE(OPTIONAL_HEADER_SIZE, coff + 16);
  headers.writeUInt16LE(0x0022, coff + 18); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
  const opt = coff + 20;
  headers.writeUInt16LE(0x20b, opt); // PE32+
  headers.writeUInt32LE(0x1000, opt + 16); // AddressOfEntryPoint
  headers.writeBigUInt64LE(0x140000000n, opt + 24); // ImageBase
  headers.writeUInt32LE(0x1000, opt + 32); // SectionAlignment
  headers.writeUInt32LE(FILE_ALIGNMENT, opt + 36); // FileAlignment
  headers.writeUInt16LE(6, opt + 40); // MajorOperatingSystemVersion
  headers.writeUInt16LE(6, opt + 48); // MajorSubsystemVersion
  headers.writeUInt32LE(0x1000 * (sections.length + 1), opt + 56); // SizeOfImage
  headers.writeUInt32LE(SYNTHETIC_HEADERS_SIZE, opt + 60); // SizeOfHeaders
  headers.writeUInt16LE(3, opt + 68); // Subsystem: console
  headers.writeBigUInt64LE(0x100000n, opt + 72); // SizeOfStackReserve
  headers.writeBigUInt64LE(0x1000n, opt + 80);
  headers.writeBigUInt64LE(0x100000n, opt + 88);
  headers.writeBigUInt64LE(0x1000n, opt + 96);
  headers.writeUInt32LE(16, opt + 108); // NumberOfRvaAndSizes
  const dataDirectories = opt + 112;
  if (options.securityDirectory) {
    headers.writeUInt32LE(options.securityDirectory[0], dataDirectories + 4 * 8);
    headers.writeUInt32LE(options.securityDirectory[1], dataDirectories + 4 * 8 + 4);
  }

  const body: Buffer[] = [];
  const placed: { name: string; pointer: number; size: number; virtual: number }[] = [];
  let pointer = SYNTHETIC_HEADERS_SIZE;
  sections.forEach((s, i) => {
    const size = align(s.data.length, FILE_ALIGNMENT);
    const padded = Buffer.alloc(size);
    s.data.copy(padded);
    body.push(padded);
    placed.push({ name: s.name, pointer, size, virtual: 0x1000 * (i + 1) });
    pointer += size;
  });
  const order = options.reverseSectionTable ? [...placed].reverse() : placed;
  order.forEach((s, i) => {
    const off = SECTION_TABLE_OFFSET + i * 40;
    headers.write(s.name.padEnd(8, '\0').slice(0, 8), off, 'latin1');
    headers.writeUInt32LE(s.size, off + 8); // VirtualSize
    headers.writeUInt32LE(s.virtual, off + 12); // VirtualAddress
    headers.writeUInt32LE(s.size, off + 16); // SizeOfRawData
    headers.writeUInt32LE(s.pointer, off + 20); // PointerToRawData
    headers.writeUInt32LE(0x60000020, off + 36); // CODE | EXECUTE | READ
  });
  return Buffer.concat([headers, ...body, options.trailing ?? Buffer.alloc(0)]);
}
