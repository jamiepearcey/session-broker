// Shared chrome, in the ArrowRef console's register: a titled toolbar with an
// explanation, bordered panels with a tone, and one honest error note.
//
// The `blurb` on every toolbar is not decoration. This console shows
// credentials and sessions, where the cost of a confident wrong assumption is
// high, so each surface says what it is looking at before showing it.

import type { LucideIcon } from "lucide-react";
import { AlertTriangle } from "lucide-react";

import { cn } from "@/lib/utils";
import { AdminError } from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";

export function Toolbar({
  title,
  blurb,
  icon: Icon,
  children,
}: {
  title: string;
  blurb: string;
  icon: LucideIcon;
  children?: React.ReactNode;
}) {
  return (
    <div className="border-b border-outline-subtle px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Icon className="h-4 w-4 shrink-0 text-primary" />
        <h1 className="text-[13px] font-semibold text-foreground">{title}</h1>
        <div className="ml-auto flex flex-wrap items-center gap-2">{children}</div>
      </div>
      <p className="mt-1 max-w-3xl text-[11.5px] text-muted-foreground">{blurb}</p>
    </div>
  );
}

// Callout backgrounds are OPAQUE tokens, not alpha washes over the accent.
//
// These panels sit on `--surface-app`, which is near-black (225 12% 4.5%), so
// `bg-warn/20` composites to roughly 14% lightness — a brown stain rather than
// an amber panel, and raising the alpha only deepens the saturation instead of
// lifting the surface. `--surface-warn` / `--surface-danger` carry the hue at a
// lightness chosen to read as a lit panel while staying dark enough for
// `--foreground` text.
const TONE = {
  plain: "border-outline-subtle bg-surface-panel",
  warn: "border-warn/60 bg-surface-warn text-warn-foreground",
  danger: "border-destructive/60 bg-surface-danger text-warn-foreground",
} as const;

export function Panel({
  tone = "plain",
  className,
  children,
}: {
  tone?: keyof typeof TONE;
  className?: string;
  children: React.ReactNode;
}) {
  return <div className={cn("rounded-md border p-3", TONE[tone], className)}>{children}</div>;
}

/**
 * One error surface, which distinguishes the three things that actually go
 * wrong here — because they send an operator to three different places.
 */
export function ErrorNote({ error }: { error: Error }) {
  const admin = error instanceof AdminError ? error : null;

  const unreachable = admin?.status === 0;
  const disabled = admin?.status === 501;
  const unauthorised = admin?.status === 401;

  return (
    <Panel tone={unreachable ? "warn" : "danger"}>
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warn" />
        <div className="space-y-1">
          <div className="text-[12px] font-medium text-foreground">
            {unreachable && "The broker is not reachable."}
            {disabled && "The admin lane is switched off."}
            {unauthorised && "That admin key was not accepted."}
            {!unreachable && !disabled && !unauthorised && "The broker refused this request."}
          </div>
          <p className="text-[11.5px] text-muted-foreground">
            {unreachable &&
              "This console talks to the broker's internal listener. Check it is running and that the dev proxy points at it. This is not an authentication problem."}
            {disabled &&
              "No admin_api_key is configured on the broker, so /admin/* refuses everything. Unconfigured means closed, not open — set one and restart."}
            {unauthorised && "Check the key, or issue a new one from the broker's configuration."}
            {!unreachable && !disabled && !unauthorised && error.message}
          </p>
          {admin && (
            <StatusBadge variant="neutral">
              {admin.status || "network"} · {admin.code}
            </StatusBadge>
          )}
        </div>
      </div>
    </Panel>
  );
}
