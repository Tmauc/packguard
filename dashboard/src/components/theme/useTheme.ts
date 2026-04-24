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

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used inside a <ThemeProvider>.");
  }
  return ctx;
}
