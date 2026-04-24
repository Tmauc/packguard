import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";
import { AddWorkspaceModal } from "@/components/layout/AddWorkspaceModal";
import { ApiError } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: { startScan: vi.fn() },
  };
});

vi.mock("sonner", () => ({
  toast: { message: vi.fn(), error: vi.fn() },
}));

import { api } from "@/lib/api";

function wrap(
  open: boolean,
  handlers: {
    onClose?: () => void;
    onStarted?: (id: string, path: string) => void;
  } = {},
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <AddWorkspaceModal
        open={open}
        onClose={handlers.onClose ?? (() => {})}
        onStarted={handlers.onStarted ?? (() => {})}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  (api.startScan as ReturnType<typeof vi.fn>).mockReset();
});

describe("AddWorkspaceModal", () => {
  it("rejects empty input with an inline error before calling the server", async () => {
    wrap(true);
    const user = userEvent.setup();
    await user.click(screen.getByTestId("add-workspace-submit"));
    expect(screen.getByTestId("add-workspace-error")).toHaveTextContent(
      /Path is required/i,
    );
    expect(api.startScan).not.toHaveBeenCalled();
  });

  it("rejects a relative path with an inline error before calling the server", async () => {
    wrap(true);
    const user = userEvent.setup();
    await user.type(
      screen.getByTestId("add-workspace-path-input"),
      "relative/path",
    );
    await user.click(screen.getByTestId("add-workspace-submit"));
    expect(screen.getByTestId("add-workspace-error")).toHaveTextContent(
      /must be absolute/i,
    );
    expect(api.startScan).not.toHaveBeenCalled();
  });

  it("shows the server's 400 message inline and keeps the modal open", async () => {
    (api.startScan as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiError(
        "bad_request",
        "bad request: path does not exist: /nowhere (no such file)",
        400,
      ),
    );
    const onClose = vi.fn();
    wrap(true, { onClose });
    const user = userEvent.setup();
    await user.type(screen.getByTestId("add-workspace-path-input"), "/nowhere");
    await user.click(screen.getByTestId("add-workspace-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("add-workspace-error")).toHaveTextContent(
        /path does not exist/i,
      ),
    );
    // Not closed — the user is expected to correct the typo.
    expect(onClose).not.toHaveBeenCalled();
  });

  it("fires onStarted with the job id + path, toasts, and closes on success", async () => {
    (api.startScan as ReturnType<typeof vi.fn>).mockResolvedValue({ id: "job-42" });
    const onClose = vi.fn();
    const onStarted = vi.fn();
    wrap(true, { onClose, onStarted });
    const user = userEvent.setup();
    await user.type(
      screen.getByTestId("add-workspace-path-input"),
      "/Users/me/proj",
    );
    await user.click(screen.getByTestId("add-workspace-submit"));
    await waitFor(() =>
      expect(api.startScan).toHaveBeenCalledWith("/Users/me/proj"),
    );
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith("job-42", "/Users/me/proj"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes when the user presses Escape", async () => {
    const onClose = vi.fn();
    wrap(true, { onClose });
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
