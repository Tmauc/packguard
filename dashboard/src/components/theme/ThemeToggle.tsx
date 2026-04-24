import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { type Theme, useTheme } from "@/components/theme/ThemeProvider";

const CYCLE: Record<Theme, Theme> = {
  light: "dark",
  dark: "system",
  system: "light",
};

const LABELS: Record<Theme, string> = {
  light: "Theme: light. Click to switch to dark.",
  dark: "Theme: dark. Click to switch to follow your OS.",
  system: "Theme: follow OS. Click to switch to light.",
};

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const next = CYCLE[theme];
  const Icon = theme === "light" ? SunIcon : theme === "dark" ? MoonIcon : MonitorIcon;
  return (
    <Button
      variant="ghost"
      size="icon"
      type="button"
      title={LABELS[theme]}
      aria-label={LABELS[theme]}
      data-theme={theme}
      data-testid="theme-toggle"
      onClick={() => setTheme(next)}
    >
      <Icon className="h-4 w-4" />
    </Button>
  );
}
