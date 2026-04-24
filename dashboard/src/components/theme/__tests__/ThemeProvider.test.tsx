import { act, render, renderHook, screen } from "@testing-library/react";
import { vi } from "vitest";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import { STORAGE_KEY, useTheme } from "@/components/theme/useTheme";

// matchMedia isn't implemented by happy-dom; drive the (prefers-color-scheme)
// media query manually so we can control whether "system" resolves light or
// dark and flip it mid-test for the reactivity check.
type Listener = (e: { matches: boolean }) => void;
type MockMQ = {
  matches: boolean;
  addEventListener: (ev: "change", cb: Listener) => void;
  removeEventListener: (ev: "change", cb: Listener) => void;
  fire: (matches: boolean) => void;
};

function installMatchMedia(initial: boolean): MockMQ {
  const listeners: Listener[] = [];
  const mq: MockMQ = {
    matches: initial,
    addEventListener: (_ev, cb) => {
      listeners.push(cb);
    },
    removeEventListener: (_ev, cb) => {
      const i = listeners.indexOf(cb);
      if (i >= 0) listeners.splice(i, 1);
    },
    fire: (matches) => {
      mq.matches = matches;
      for (const l of listeners) l({ matches });
    },
  };
  window.matchMedia = vi.fn().mockReturnValue(mq) as unknown as typeof window.matchMedia;
  return mq;
}

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
});

function Probe() {
  const { theme, resolved } = useTheme();
  return (
    <div>
      <span data-testid="theme">{theme}</span>
      <span data-testid="resolved">{resolved}</span>
    </div>
  );
}

describe("ThemeProvider", () => {
  it("defaults to 'system' when localStorage has no preference", () => {
    installMatchMedia(false);
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(screen.getByTestId("theme").textContent).toBe("system");
    expect(screen.getByTestId("resolved").textContent).toBe("light");
  });

  it("persists explicit user selections to localStorage", () => {
    installMatchMedia(false);
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    act(() => result.current.setTheme("dark"));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("dark");
    expect(result.current.theme).toBe("dark");
    expect(result.current.resolved).toBe("dark");
  });

  it("resolves 'system' against matchMedia and reacts to OS-level flips", () => {
    const mq = installMatchMedia(false);
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(screen.getByTestId("resolved").textContent).toBe("light");
    // OS switches to dark mode while our preference stays on system —
    // the resolved value must follow without the user touching anything.
    act(() => mq.fire(true));
    expect(screen.getByTestId("resolved").textContent).toBe("dark");
  });

  it("applies the 'dark' class to <html> when resolved is dark", () => {
    installMatchMedia(true);
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    );
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
