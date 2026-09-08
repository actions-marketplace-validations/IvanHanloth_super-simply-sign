/** Crash-safe file output: a signed image is either fully written or not there at all. */
import { randomBytes } from 'node:crypto';
import { chmod, open, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';

/**
 * Write `data` to `target` atomically: a fresh temp file in the same
 * directory, fsync, then rename over the target. An existing target's mode
 * is preserved; a crash mid-way leaves the target untouched.
 */
export async function writeFileAtomic(target: string, data: Uint8Array): Promise<void> {
  const dir = path.dirname(target);
  const temp = path.join(dir, `.${path.basename(target)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  let mode: number | undefined;
  try {
    mode = (await stat(target)).mode & 0o777;
  } catch {
    // no existing file: default mode
  }
  const handle = await open(temp, 'wx', mode ?? 0o644);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    if (mode !== undefined && process.platform !== 'win32') await chmod(temp, mode);
    await rename(temp, target);
  } catch (err) {
    await unlink(temp).catch(() => undefined);
    throw err;
  }
}

/** Write `<original>.orig`; refuses to overwrite a backup that already exists. */
export async function writeBackup(original: string, data: Uint8Array): Promise<string> {
  const backupPath = `${original}.orig`;
  const handle = await open(backupPath, 'wx');
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  return backupPath;
}
