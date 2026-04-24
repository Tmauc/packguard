import { createContext, useContext } from "react";

export type Theme = "light" | "dark" | "system";
export type Resolved = "light" | "dark";

export type ThemeContextValue = {
  theme: Theme;
  resolved: Resolved;
  setTheme: (t: Theme) => void;
};

export const STORAGE_KEY = "packguard.theme";

export const ThemeContext = createContext<ThemeContextValue | null>(null);

// Safe defaults returned when a component calls useTheme() without an
// ancestor ThemeProvider. Production code always mounts one high in
// main.tsx, but tests that render a leaf component in isolation don't —
// rather than force every test to wrap, we fall back to a "light,
// unchangeable" context. setTheme is a no-op so misuse in prod still
// shows up visually (the toggle will click and do nothing) rather than
// crashing the whole page.
const DEFAULT_CONTEXT: ThemeContextValue = {
  theme: "system",
  resolved: "light",
  setTheme: () => {},
};

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  return ctx ?? DEFAULT_CONTEXT;
}
