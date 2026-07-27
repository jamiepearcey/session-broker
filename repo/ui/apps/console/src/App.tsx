// The session-broker console.
//
// Structure copied from ArrowRef's console (`infrastructure/query-cache/repo/ui`):
// a fixed left rail, one view at a time in the main pane, the same dark token
// set and badge register. Same reason it works there — an operator tool is a
// small number of dense surfaces, not a navigable app.
//
// The one structural difference is the gate below. ArrowRef's console talks to
// a node that authenticates per request; this one holds the admin key, the
// credential that can mint credentials. So the key is asked for up front, kept
// in memory only, and forgotten when the tab closes.

import { useState } from "react";
import { HeartPulse, KeyRound, ShieldCheck, Users } from "lucide-react";

import { Keys } from "@/views/Keys";
import { Sessions } from "@/views/Sessions";
import { CustodyView } from "@/views/CustodyView";
import { hasAdminKey, setAdminKey } from "@/lib/api";
import { cn } from "@/lib/utils";

type ViewId = "keys" | "sessions" | "custody";

const VIEWS = [
  { id: "keys" as const, label: "API keys", icon: KeyRound },
  { id: "sessions" as const, label: "Sessions", icon: Users },
  { id: "custody" as const, label: "Custody", icon: HeartPulse },
];

export default function App() {
  const [view, setView] = useState<ViewId>("keys");
  const [unlocked, setUnlocked] = useState(hasAdminKey());

  if (!unlocked) {
    return <Unlock onUnlocked={() => setUnlocked(true)} />;
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-surface-app text-foreground">
      <aside className="flex w-52 shrink-0 flex-col border-r border-outline-subtle bg-surface-panel">
        <div className="flex items-center gap-2 border-b border-outline-subtle px-3 py-3">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <div className="min-w-0">
            <div className="truncate text-[12px] font-semibold">session-broker</div>
            <div className="truncate text-[10px] text-muted-foreground">console</div>
          </div>
        </div>
        <nav className="flex flex-col gap-0.5 p-2">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              type="button"
              onClick={() => setView(v.id)}
              className={cn(
                "flex items-center gap-2 rounded-md px-2 py-1.5 text-[11.5px]",
                view === v.id
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-surface-hover hover:text-foreground",
              )}
            >
              <v.icon className="h-3.5 w-3.5 shrink-0" />
              {v.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto border-t border-outline-subtle p-2">
          <button
            type="button"
            className="w-full rounded-md px-2 py-1.5 text-left text-[11px] text-muted-foreground hover:text-foreground"
            onClick={() => {
              setAdminKey(null);
              setUnlocked(false);
            }}
          >
            Forget admin key
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        {view === "keys" && <Keys />}
        {view === "sessions" && <Sessions />}
        {view === "custody" && <CustodyView />}
      </main>
    </div>
  );
}

/**
 * The key gate.
 *
 * Not a login — the broker's admin lane has no session of its own, only a
 * shared secret. Saying so plainly matters: an operator who thinks this is a
 * login will look for a "forgot password" that does not exist.
 */
function Unlock({ onUnlocked }: { onUnlocked: () => void }) {
  const [value, setValue] = useState("");

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-surface-app text-foreground">
      <form
        className="w-full max-w-md space-y-3 rounded-md border border-outline-subtle bg-surface-panel p-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (!value.trim()) return;
          setAdminKey(value);
          setValue("");
          onUnlocked();
        }}
      >
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <h1 className="text-[13px] font-semibold">session-broker console</h1>
        </div>
        <p className="text-[11.5px] text-muted-foreground">
          Paste the broker&apos;s <code className="font-mono">admin_api_key</code>. It is held in
          memory for this tab only — never written to storage or a cookie — so closing the tab
          forgets it. This is the credential that can issue other credentials, so it is worth
          treating that way.
        </p>
        <input
          className="input w-full"
          type="password"
          autoFocus
          placeholder="admin_api_key"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <button type="submit" className="btn-primary w-full justify-center" disabled={!value.trim()}>
          Unlock
        </button>
      </form>
    </div>
  );
}
