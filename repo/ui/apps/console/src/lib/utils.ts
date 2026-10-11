import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** "a b, c" → ["a", "b", "c"]. Scopes, indexes and roles are typed as words; the
 *  broker owns the real validation, this only splits. */
export function words(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean);
}

/** A whole number of hours from a text field → seconds. Blank is `undefined`
 *  ("use the broker's default"); anything else that is not a positive whole
 *  number is `null`, so the caller can refuse it instead of sending a guess. */
export function hoursToSecs(text: string): number | undefined | null {
  const t = text.trim();
  if (!t) return undefined;
  if (!/^\d+$/.test(t) || Number(t) < 1) return null;
  return Number(t) * 3600;
}
