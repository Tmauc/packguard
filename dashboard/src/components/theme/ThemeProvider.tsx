import { useCallback, useEffect, useMemo, useState } from "react";
import {
  STORAGE_KEY,
  ThemeContext,
  type Resolved,
  type Theme,
  type ThemeContextValue,
} from "@/components/theme/useTheme";

function readStoredTheme(): Theme {
  if (typeof window === "undefined") return "system";
  const raw = window.localStorage.getItem(STORAGE_KEY);
  return raw === "light" || raw === "dark" || raw === "system" ? raw : "system";
}

function systemResolved(): Resolved {
  if (typeof window === "undefined" || !window.matchMedia) return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyDocumentClass(resolved: Resolved) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => readStoredTheme());
  const [systemTick, setSystemTick] = useState(0);

  const resolved: Resolved = useMemo(() => {
    if (theme === "system") return systemResolved();
    return theme;
    // Re-run when the OS-level preference flips while `system` is active.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [theme, systemTick]);

  useEffect(() => {
    applyDocumentClass(resolved);
  }, [resolved]);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => setSystemTick((t) => t + 1);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, t);
    }
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, resolved, setTheme }),
    [theme, resolved, setTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
