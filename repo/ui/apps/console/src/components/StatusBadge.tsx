import { cn } from "@/lib/utils";

export type StateVariant = "ok" | "warn" | "error" | "info" | "active" | "neutral";

const VARIANT: Record<StateVariant, string> = {
  ok: "border-ok/40 bg-ok/15 text-ok",
  warn: "border-warn/40 bg-warn/15 text-warn",
  error: "border-destructive/45 bg-destructive/15 text-destructive",
  info: "border-info/40 bg-info/15 text-info",
  active: "border-primary/45 bg-primary/15 text-primary",
  neutral: "border-outline-strong bg-surface-toolbar text-muted-foreground",
};

export function StatusBadge({
  variant,
  children,
  pulse,
  className,
}: {
  variant: StateVariant;
  children: React.ReactNode;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10.5px] font-medium tabular-nums",
        VARIANT[variant],
        className,
      )}
    >
      {pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-70" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />
        </span>
      )}
      {children}
    </span>
  );
}
