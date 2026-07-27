/**
 * The subset of ArrowRef's ten-plane palette this app uses (see
 * src/index.css for the full token set, copied verbatim). Each of the four
 * views gets its own plane so the chrome doesn't read as one mush — the
 * same reasoning as the reference (query-cache/repo/ui/src/lib/planes.ts).
 */
export type PlaneId = 'signals' | 'compute' | 'messaging' | 'budget';

export const PLANES: Record<PlaneId, { label: string }> = {
  signals: { label: 'Session' },
  compute: { label: 'Race' },
  messaging: { label: 'Refresh' },
  budget: { label: 'Failures' },
};
