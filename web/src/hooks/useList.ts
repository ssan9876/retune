import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { ListResponse } from "../api/types";

/** useList fetches one page of a listing endpoint and re-fetches on change. */
export function useList<T>(path: string, params: Record<string, string | number | undefined> = {}) {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [offset, setOffset] = useState(0);
  const [reloadToken, setReloadToken] = useState(0);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  query.set("offset", String(offset));
  const search = query.toString();

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .get<ListResponse<T>>(`${path}?${search}`)
      .then((page) => {
        if (cancelled) return;
        setItems(page.items);
        setTotal(page.total);
        setError(null);
        setLastUpdated(new Date());
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [path, search, reloadToken]);

  const reload = useCallback(() => setReloadToken((n) => n + 1), []);
  return { items, total, loading, error, offset, setOffset, reload, lastUpdated };
}
