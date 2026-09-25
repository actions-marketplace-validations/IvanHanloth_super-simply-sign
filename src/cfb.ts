/**
 * OLE structured storage — the Compound File Binary Format (MS-CFB) that an
 * MSI package is. A compound file is a tiny file system: fixed-size sectors,
 * a FAT chaining them, a "mini stream" (itself a chained stream) that holds
 * small streams in 64-byte mini sectors with its own mini FAT, and a
 * directory of 128-byte entries forming a tree of storages and streams.
 *
 * The reader materialises that tree with every stream's bytes; the writer
 * lays out a fresh file from such a tree. Layout is deliberately *not*
 * preserved — an MSI signature covers stream contents and directory
 * metadata (names, CLSIDs, state bits, times), never sector placement — so
 * re-laying the file out is the simplest correct way to add a stream.
 */
import { asBuffer } from './der.ts';

export class CfbError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CfbError';
  }
}

export const CFB_MAGIC = Buffer.from('d0cf11e0a1b11ae1', 'hex');

export function isCompoundFile(bytes: Uint8Array): boolean {
  return bytes.length >= 8 && asBuffer(bytes).subarray(0, 8).equals(CFB_MAGIC);
}

const FREESECT = 0xffffffff;
const ENDOFCHAIN = 0xfffffffe;
const FATSECT = 0xfffffffd;
const DIFSECT = 0xfffffffc;
const MAXREGSECT = 0xfffffffa;
const NOSTREAM = 0xffffffff;

const HEADER_SIZE = 512;
const MINI_SECTOR_SHIFT = 6;
const MINI_SECTOR_SIZE = 1 << MINI_SECTOR_SHIFT;
const MINI_STREAM_CUTOFF = 4096;
const DIRENT_SIZE = 128;
const DIFAT_IN_HEADER = 109;
/** 64 bytes of UTF-16LE including the terminator. */
const MAX_NAME_UNITS = 31;
const MAX_DEPTH = 64;

export const ENTRY_STORAGE = 1;
export const ENTRY_STREAM = 2;
export const ENTRY_ROOT = 5;
export type CfbEntryType = typeof ENTRY_STORAGE | typeof ENTRY_STREAM | typeof ENTRY_ROOT;

export interface CfbEntry {
  readonly name: string;
  /** The UTF-16LE name bytes without the terminator — what MSI hashing sorts by and hashes. */
  readonly nameRaw: Buffer;
  readonly type: CfbEntryType;
  readonly clsid: Buffer;
  readonly stateBits: number;
  /** FILETIME, 8 bytes, kept as raw bytes. */
  readonly creationTime: Buffer;
  readonly modifiedTime: Buffer;
  /** Stream content; empty for storages and the root. */
  readonly data: Buffer;
  /** Children of a storage or the root; empty for streams. */
  readonly children: readonly CfbEntry[];
}

export interface CompoundFile {
  readonly root: CfbEntry;
  readonly majorVersion: 3 | 4;
}

export function utf16le(s: string): Buffer {
  return Buffer.from(s, 'utf16le');
}

/** A new stream entry with zeroed metadata (what a freshly added signature stream carries). */
export function makeStream(name: string, data: Uint8Array): CfbEntry {
  return {
    name,
    nameRaw: utf16le(name),
    type: ENTRY_STREAM,
    clsid: Buffer.alloc(16),
    stateBits: 0,
    creationTime: Buffer.alloc(8),
    modifiedTime: Buffer.alloc(8),
    data: Buffer.from(asBuffer(data)),
    children: [],
  };
}

/** `entry` with a different child list. */
export function withChildren(entry: CfbEntry, children: readonly CfbEntry[]): CfbEntry {
  return { ...entry, children };
}

// ---- reading --------------------------------------------------------------

interface RawEntry {
  readonly name: string;
  readonly nameRaw: Buffer;
  readonly type: number;
  readonly left: number;
  readonly right: number;
  readonly child: number;
  readonly clsid: Buffer;
  readonly stateBits: number;
  readonly creationTime: Buffer;
  readonly modifiedTime: Buffer;
  readonly start: number;
  readonly size: number;
}

/** Parse a compound file completely (every stream is read into memory). */
export function parseCompoundFile(bytes: Uint8Array): CompoundFile {
  const b = asBuffer(bytes);
  if (b.length < HEADER_SIZE || !isCompoundFile(b)) throw new CfbError('not an OLE compound file (bad signature)');
  const majorVersion = b.readUInt16LE(0x1a);
  const sectorShift = b.readUInt16LE(0x1e);
  if (!((majorVersion === 3 && sectorShift === 9) || (majorVersion === 4 && sectorShift === 12))) {
    throw new CfbError(`unsupported compound file version ${majorVersion} / sector shift ${sectorShift}`);
  }
  if (b.readUInt16LE(0x20) !== MINI_SECTOR_SHIFT) throw new CfbError('unsupported mini sector size');
  const sectorSize = 1 << sectorShift;
  const entriesPerSector = sectorSize / 4;
  const numFatSectors = b.readUInt32LE(0x2c);
  const firstDirSector = b.readUInt32LE(0x30);
  const miniCutoff = b.readUInt32LE(0x38);
  const firstMiniFatSector = b.readUInt32LE(0x3c);
  const numMiniFatSectors = b.readUInt32LE(0x40);
  const firstDifatSector = b.readUInt32LE(0x44);
  const numDifatSectors = b.readUInt32LE(0x48);

  const sector = (n: number): Buffer => {
    if (n > MAXREGSECT) throw new CfbError(`invalid sector number 0x${n.toString(16)}`);
    const off = (n + 1) * sectorSize;
    if (off + sectorSize > b.length) throw new CfbError(`sector ${n} lies beyond the end of the file`);
    return b.subarray(off, off + sectorSize);
  };

  // DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
  const difat: number[] = [];
  for (let i = 0; i < DIFAT_IN_HEADER; i++) {
    const v = b.readUInt32LE(0x4c + i * 4);
    if (v <= MAXREGSECT) difat.push(v);
  }
  let ds = firstDifatSector;
  const seenDifat = new Set<number>();
  for (let i = 0; i < numDifatSectors; i++) {
    if (ds > MAXREGSECT) break;
    if (seenDifat.has(ds)) throw new CfbError('cyclic DIFAT chain');
    seenDifat.add(ds);
    const s = sector(ds);
    for (let j = 0; j < entriesPerSector - 1; j++) {
      const v = s.readUInt32LE(j * 4);
      if (v <= MAXREGSECT) difat.push(v);
    }
    ds = s.readUInt32LE(sectorSize - 4);
  }
  if (difat.length < numFatSectors) throw new CfbError('the DIFAT lists fewer FAT sectors than the header announces');

  const fat = new Uint32Array(numFatSectors * entriesPerSector);
  for (let i = 0; i < numFatSectors; i++) {
    const s = sector(difat[i]!);
    for (let j = 0; j < entriesPerSector; j++) fat[i * entriesPerSector + j] = s.readUInt32LE(j * 4);
  }

  const chain = (start: number, table: Uint32Array, what: string): number[] => {
    const out: number[] = [];
    let cur = start;
    while (cur <= MAXREGSECT) {
      if (out.length >= table.length) throw new CfbError(`cyclic sector chain in ${what}`);
      out.push(cur);
      if (cur >= table.length) throw new CfbError(`${what} refers to sector ${cur} outside the FAT`);
      cur = table[cur]!;
    }
    return out;
  };

  const readChain = (start: number, size: number, what: string): Buffer => {
    const sectors = chain(start, fat, what);
    if (size > sectors.length * sectorSize) throw new CfbError(`${what} is longer than its sector chain`);
    return Buffer.concat(sectors.map(sector)).subarray(0, size);
  };

  let miniFat = new Uint32Array(0);
  if (numMiniFatSectors > 0 && firstMiniFatSector <= MAXREGSECT) {
    const sectors = chain(firstMiniFatSector, fat, 'mini FAT');
    miniFat = new Uint32Array(sectors.length * entriesPerSector);
    sectors.forEach((n, i) => {
      const s = sector(n);
      for (let j = 0; j < entriesPerSector; j++) miniFat[i * entriesPerSector + j] = s.readUInt32LE(j * 4);
    });
  }

  const dirBytes = Buffer.concat(chain(firstDirSector, fat, 'directory').map(sector));
  const entries: (RawEntry | null)[] = [];
  for (let off = 0; off + DIRENT_SIZE <= dirBytes.length; off += DIRENT_SIZE) {
    const e = dirBytes.subarray(off, off + DIRENT_SIZE);
    const type = e[0x42]!;
    if (type === 0) {
      entries.push(null);
      continue;
    }
    if (type !== ENTRY_STORAGE && type !== ENTRY_STREAM && type !== ENTRY_ROOT) throw new CfbError(`unknown directory entry type ${type}`);
    const nameLen = e.readUInt16LE(0x40);
    if (nameLen < 2 || nameLen > 64 || nameLen % 2 !== 0) throw new CfbError('directory entry with an invalid name length');
    const nameRaw = Buffer.from(e.subarray(0, nameLen - 2));
    const size = majorVersion === 3 ? e.readUInt32LE(0x78) : Number(e.readBigUInt64LE(0x78));
    if (size > b.length) throw new CfbError('directory entry claims a stream larger than the file');
    entries.push({
      name: nameRaw.toString('utf16le'),
      nameRaw,
      type,
      left: e.readUInt32LE(0x44),
      right: e.readUInt32LE(0x48),
      child: e.readUInt32LE(0x4c),
      clsid: Buffer.from(e.subarray(0x50, 0x60)),
      stateBits: e.readUInt32LE(0x60),
      creationTime: Buffer.from(e.subarray(0x64, 0x6c)),
      modifiedTime: Buffer.from(e.subarray(0x6c, 0x74)),
      start: e.readUInt32LE(0x74),
      size,
    });
  }
  const rootRaw = entries[0];
  if (!rootRaw || rootRaw.type !== ENTRY_ROOT) throw new CfbError('the first directory entry is not the root storage');

  const miniStream = rootRaw.size > 0 ? readChain(rootRaw.start, rootRaw.size, 'mini stream') : Buffer.alloc(0);
  const readMini = (start: number, size: number, what: string): Buffer => {
    const sectors = chain(start, miniFat, what);
    if (size > sectors.length * MINI_SECTOR_SIZE) throw new CfbError(`${what} is longer than its mini sector chain`);
    const parts = sectors.map((n) => {
      const off = n * MINI_SECTOR_SIZE;
      if (off + MINI_SECTOR_SIZE > miniStream.length) throw new CfbError(`${what} refers to mini sector ${n} beyond the mini stream`);
      return miniStream.subarray(off, off + MINI_SECTOR_SIZE);
    });
    return Buffer.concat(parts).subarray(0, size);
  };
  const streamData = (e: RawEntry): Buffer => {
    if (e.size === 0) return Buffer.alloc(0);
    const what = `stream "${e.name}"`;
    return Buffer.from(e.size < miniCutoff ? readMini(e.start, e.size, what) : readChain(e.start, e.size, what));
  };

  const visited = new Set<number>();
  const siblings = (first: number): RawEntry[] => {
    // Flatten the red-black tree hanging off `first` into a list (order is irrelevant here).
    const out: RawEntry[] = [];
    const stack = [first];
    while (stack.length > 0) {
      const i = stack.pop()!;
      if (i > MAXREGSECT) continue;
      if (visited.has(i)) throw new CfbError(`directory entry ${i} is referenced twice`);
      visited.add(i);
      const e = entries[i];
      if (!e) throw new CfbError(`directory tree points at empty entry ${i}`);
      if (e.type === ENTRY_ROOT) throw new CfbError('the root entry appears inside the tree');
      out.push(e);
      stack.push(e.left, e.right);
    }
    return out;
  };
  const build = (e: RawEntry, depth: number): CfbEntry => {
    if (depth > MAX_DEPTH) throw new CfbError('storage nesting is too deep');
    const isStream = e.type === ENTRY_STREAM;
    const children = isStream ? [] : siblings(e.child).map((c) => build(c, depth + 1));
    if (isStream && e.child <= MAXREGSECT) throw new CfbError(`stream "${e.name}" has children`);
    return {
      name: e.name,
      nameRaw: e.nameRaw,
      type: e.type as CfbEntryType,
      clsid: e.clsid,
      stateBits: e.stateBits,
      creationTime: e.creationTime,
      modifiedTime: e.modifiedTime,
      data: isStream ? streamData(e) : Buffer.alloc(0),
      children,
    };
  };
  visited.add(0);
  return { root: build(rootRaw, 0), majorVersion };
}

// ---- writing --------------------------------------------------------------

/** One UTF-16 unit uppercased, as the directory tree ordering (MS-CFB §2.6.4) wants. */
function upper(unit: number): number {
  const u = String.fromCharCode(unit).toUpperCase();
  return u.length === 1 ? u.charCodeAt(0) : unit;
}

/** Directory tree ordering: shorter names first, then case-insensitively by UTF-16 unit. */
export function treeNameCompare(a: CfbEntry, b: CfbEntry): number {
  if (a.nameRaw.length !== b.nameRaw.length) return a.nameRaw.length - b.nameRaw.length;
  for (let i = 0; i < a.nameRaw.length; i += 2) {
    const d = upper(a.nameRaw.readUInt16LE(i)) - upper(b.nameRaw.readUInt16LE(i));
    if (d !== 0) return d;
  }
  return 0;
}

interface DirRecord {
  readonly entry: CfbEntry;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

/** Serialise a compound file. Sector layout: streams, mini stream, mini FAT, directory, FAT, DIFAT. */
export function writeCompoundFile(file: CompoundFile): Buffer {
  const sectorShift = file.majorVersion === 4 ? 12 : 9;
  const sectorSize = 1 << sectorShift;
  const entriesPerSector = sectorSize / 4;

  // 1. Directory records, each storage's children as a balanced binary tree.
  const records: DirRecord[] = [];
  const place = (entry: CfbEntry, depth: number): number => {
    if (depth > MAX_DEPTH) throw new CfbError('storage nesting is too deep');
    if (entry.nameRaw.length > MAX_NAME_UNITS * 2 || entry.nameRaw.length % 2 !== 0) throw new CfbError(`invalid entry name "${entry.name}"`);
    const id = records.length;
    records.push({ entry, left: NOSTREAM, right: NOSTREAM, child: NOSTREAM, start: ENDOFCHAIN, size: 0 });
    if (entry.type !== ENTRY_STREAM) {
      const kids = [...entry.children].sort(treeNameCompare);
      for (let i = 1; i < kids.length; i++) {
        if (treeNameCompare(kids[i - 1]!, kids[i]!) === 0) throw new CfbError(`duplicate entry name "${kids[i]!.name}"`);
      }
      const ids = kids.map((k) => place(k, depth + 1));
      const tree = (lo: number, hi: number): number => {
        if (lo > hi) return NOSTREAM;
        const mid = (lo + hi) >> 1;
        const rec = records[ids[mid]!]!;
        rec.left = tree(lo, mid - 1);
        rec.right = tree(mid + 1, hi);
        return ids[mid]!;
      };
      records[id]!.child = tree(0, ids.length - 1);
    } else if (entry.children.length > 0) {
      throw new CfbError(`stream "${entry.name}" cannot have children`);
    }
    return id;
  };
  if (file.root.type !== ENTRY_ROOT) throw new CfbError('the root entry must be of type root');
  place(file.root, 0);

  // 2. Sector data. `fat[i]` is the FAT entry of sector i.
  const sectors: Buffer[] = [];
  const fat: number[] = [];
  const appendChain = (data: Buffer): number => {
    if (data.length === 0) return ENDOFCHAIN;
    const start = sectors.length;
    const count = Math.ceil(data.length / sectorSize);
    for (let i = 0; i < count; i++) {
      const s = Buffer.alloc(sectorSize);
      data.copy(s, 0, i * sectorSize, Math.min(data.length, (i + 1) * sectorSize));
      sectors.push(s);
      fat.push(i < count - 1 ? start + i + 1 : ENDOFCHAIN);
    }
    return start;
  };
  const miniParts: Buffer[] = [];
  const miniFat: number[] = [];
  for (const rec of records) {
    if (rec.entry.type !== ENTRY_STREAM) continue;
    const data = rec.entry.data;
    rec.size = data.length;
    if (data.length === 0) {
      rec.start = ENDOFCHAIN;
    } else if (data.length < MINI_STREAM_CUTOFF) {
      const count = Math.ceil(data.length / MINI_SECTOR_SIZE);
      rec.start = miniFat.length;
      const padded = Buffer.alloc(count * MINI_SECTOR_SIZE);
      data.copy(padded);
      miniParts.push(padded);
      for (let i = 0; i < count; i++) miniFat.push(i < count - 1 ? miniFat.length + 1 : ENDOFCHAIN);
    } else {
      rec.start = appendChain(data);
    }
  }
  const miniStream = Buffer.concat(miniParts);
  const rootRecord = records[0]!;
  rootRecord.start = appendChain(miniStream);
  rootRecord.size = miniStream.length;

  const u32s = (values: readonly number[]): Buffer => {
    const out = Buffer.alloc(values.length * 4);
    values.forEach((v, i) => out.writeUInt32LE(v >>> 0, i * 4));
    return out;
  };
  const firstMiniFatSector = appendChain(u32s(miniFat));
  const numMiniFatSectors = miniFat.length === 0 ? 0 : Math.ceil((miniFat.length * 4) / sectorSize);

  // 3. Directory sectors.
  const numDirSectors = Math.ceil((records.length * DIRENT_SIZE) / sectorSize);
  const dir = Buffer.alloc(numDirSectors * sectorSize);
  for (let i = 0; i < (numDirSectors * sectorSize) / DIRENT_SIZE; i++) {
    const off = i * DIRENT_SIZE;
    const rec = records[i];
    if (!rec) {
      dir.writeUInt32LE(NOSTREAM, off + 0x44);
      dir.writeUInt32LE(NOSTREAM, off + 0x48);
      dir.writeUInt32LE(NOSTREAM, off + 0x4c);
      continue;
    }
    const e = rec.entry;
    e.nameRaw.copy(dir, off);
    dir.writeUInt16LE(e.nameRaw.length + 2, off + 0x40);
    dir[off + 0x42] = e.type;
    dir[off + 0x43] = 1; // black; readers do not rely on colours (MS-CFB §2.6.4)
    dir.writeUInt32LE(rec.left, off + 0x44);
    dir.writeUInt32LE(rec.right, off + 0x48);
    dir.writeUInt32LE(rec.child, off + 0x4c);
    e.clsid.copy(dir, off + 0x50, 0, 16);
    dir.writeUInt32LE(e.stateBits >>> 0, off + 0x60);
    e.creationTime.copy(dir, off + 0x64, 0, 8);
    e.modifiedTime.copy(dir, off + 0x6c, 0, 8);
    dir.writeUInt32LE(rec.start, off + 0x74);
    dir.writeBigUInt64LE(BigInt(rec.size), off + 0x78);
  }
  const firstDirSector = appendChain(dir);

  // 4. FAT and DIFAT sizes depend on each other; iterate to a fixed point.
  const dataSectors = sectors.length;
  let numFatSectors = 0;
  let numDifatSectors = 0;
  for (;;) {
    const total = dataSectors + numFatSectors + numDifatSectors;
    const needFat = Math.ceil(total / entriesPerSector);
    const needDifat = needFat > DIFAT_IN_HEADER ? Math.ceil((needFat - DIFAT_IN_HEADER) / (entriesPerSector - 1)) : 0;
    if (needFat === numFatSectors && needDifat === numDifatSectors) break;
    numFatSectors = needFat;
    numDifatSectors = needDifat;
  }
  const fatStart = dataSectors;
  const difatStart = dataSectors + numFatSectors;
  const fatTable: number[] = new Array<number>(numFatSectors * entriesPerSector).fill(FREESECT);
  fat.forEach((v, i) => (fatTable[i] = v));
  for (let i = 0; i < numFatSectors; i++) fatTable[fatStart + i] = FATSECT;
  for (let i = 0; i < numDifatSectors; i++) fatTable[difatStart + i] = DIFSECT;
  const fatSectorNumbers = Array.from({ length: numFatSectors }, (_, i) => fatStart + i);

  // 5. Header.
  const header = Buffer.alloc(sectorSize);
  CFB_MAGIC.copy(header, 0);
  header.writeUInt16LE(0x003e, 0x18);
  header.writeUInt16LE(file.majorVersion, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(sectorShift, 0x1e);
  header.writeUInt16LE(MINI_SECTOR_SHIFT, 0x20);
  header.writeUInt32LE(file.majorVersion === 4 ? numDirSectors : 0, 0x28);
  header.writeUInt32LE(numFatSectors, 0x2c);
  header.writeUInt32LE(firstDirSector, 0x30);
  header.writeUInt32LE(0, 0x34);
  header.writeUInt32LE(MINI_STREAM_CUTOFF, 0x38);
  header.writeUInt32LE(firstMiniFatSector, 0x3c);
  header.writeUInt32LE(numMiniFatSectors, 0x40);
  header.writeUInt32LE(numDifatSectors > 0 ? difatStart : ENDOFCHAIN, 0x44);
  header.writeUInt32LE(numDifatSectors, 0x48);
  for (let i = 0; i < DIFAT_IN_HEADER; i++) header.writeUInt32LE(fatSectorNumbers[i] ?? FREESECT, 0x4c + i * 4);

  // 6. Assemble.
  const parts: Buffer[] = [header, ...sectors];
  for (let i = 0; i < numFatSectors; i++) parts.push(u32s(fatTable.slice(i * entriesPerSector, (i + 1) * entriesPerSector)));
  const perDifat = entriesPerSector - 1;
  for (let i = 0; i < numDifatSectors; i++) {
    const slice = fatSectorNumbers.slice(DIFAT_IN_HEADER + i * perDifat, DIFAT_IN_HEADER + (i + 1) * perDifat);
    while (slice.length < perDifat) slice.push(FREESECT);
    slice.push(i < numDifatSectors - 1 ? difatStart + i + 1 : ENDOFCHAIN);
    parts.push(u32s(slice));
  }
  return Buffer.concat(parts);
}
