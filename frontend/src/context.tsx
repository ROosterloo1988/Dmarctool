import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, setCsrf } from "./api";
import type { DomainSummary, Me } from "./types";

interface AppCtx {
  me: Me;
  isAdmin: boolean;
  domains: DomainSummary[];
  domain: string | null;
  setDomain: (d: string) => void;
}

const Ctx = createContext<AppCtx | null>(null);
const KEY = "dmarc.domain";

function stored(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function AppProvider({ me, children }: { me: Me; children: ReactNode }) {
  const { data: domains = [] } = useQuery({ queryKey: ["domains"], queryFn: () => api<DomainSummary[]>("/api/domains") });
  const [domain, setDomainState] = useState<string | null>(stored());

  useEffect(() => {
    if (domains.length && (!domain || !domains.some((d) => d.name === domain))) setDomainState(domains[0].name);
  }, [domains, domain]);

  const setDomain = (d: string) => {
    setDomainState(d);
    try {
      localStorage.setItem(KEY, d);
    } catch {
      /* private mode */
    }
  };
  return <Ctx.Provider value={{ me, isAdmin: me.role === "admin", domains, domain, setDomain }}>{children}</Ctx.Provider>;
}

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useApp outside AppProvider");
  return c;
}

export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const me = await api<Me>("/api/me");
      setCsrf(me.csrf);
      return me;
    },
    retry: false,
    staleTime: 5 * 60_000,
  });
}
