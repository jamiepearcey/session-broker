import { useEffect, useState } from 'react';

/**
 * Trivial hash router — per the porting brief, no router dependency. Four
 * views, one hash segment each; anything unrecognised falls back to
 * `session`.
 */
export type ViewId = 'session' | 'race' | 'refresh' | 'failures';

const DEFAULT_VIEW: ViewId = 'session';

const VIEWS: readonly ViewId[] = ['session', 'race', 'refresh', 'failures'];

export const ROUTE_PATH: Record<ViewId, string> = {
  session: '/session',
  race: '/race',
  refresh: '/refresh',
  failures: '/failures',
};

function parseHash(hash: string): ViewId {
  const id = hash.replace(/^#\/?/, '');
  return (VIEWS as readonly string[]).includes(id) ? (id as ViewId) : DEFAULT_VIEW;
}

export function useRoute(): [ViewId, (view: ViewId) => void] {
  const [view, setView] = useState<ViewId>(() => parseHash(window.location.hash));

  useEffect(() => {
    if (!window.location.hash) {
      window.location.hash = `#/${DEFAULT_VIEW}`;
    }
    const onHashChange = () => setView(parseHash(window.location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const navigate = (next: ViewId) => {
    window.location.hash = `#/${next}`;
  };

  return [view, navigate];
}
