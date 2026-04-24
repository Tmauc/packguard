import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import { ThemeToggle } from "@/components/theme/ThemeToggle";

function installMatchMedia(matches: boolean) {
  const mq = {
    matches,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
  window.matchMedia = vi.fn().mockReturnValue(mq) as unknown as typeof window.matchMedia;
}

function wrap() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
  installMatchMedia(false);
});

describe("ThemeToggle", () => {
  it("cycles light → dark → system → light on successive clicks", async () => {
    window.localStorage.setItem("packguard.theme", "light");
    wrap();
    const toggle = screen.getByTestId("theme-toggle");
    expect(toggle.getAttribute("data-theme")).toBe("light");
    const user = userEvent.setup();
    await user.click(toggle);
    expect(screen.getByTestId("theme-toggle").getAttribute("data-theme")).toBe("dark");
    await user.click(screen.getByTestId("theme-toggle"));
    expect(screen.getByTestId("theme-toggle").getAttribute("data-theme")).toBe("system");
    await user.click(screen.getByTestId("theme-toggle"));
    expect(screen.getByTestId("theme-toggle").getAttribute("data-theme")).toBe("light");
  });

  it("renders an icon and a descriptive title matching the current state", () => {
    window.localStorage.setItem("packguard.theme", "dark");
    wrap();
    const toggle = screen.getByTestId("theme-toggle");
    // The toggle's title doubles as the hover-tooltip and the aria-label;
    // it must spell out both the current state and the next action so a
    // blind user can reason about the effect of clicking it.
    expect(toggle.getAttribute("title")).toMatch(/Theme: dark/i);
    expect(toggle.getAttribute("title")).toMatch(/switch to follow your OS/i);
    expect(toggle.querySelector("svg")).not.toBeNull();
  });
});
