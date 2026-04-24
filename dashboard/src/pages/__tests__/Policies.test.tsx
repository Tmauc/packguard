import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { PoliciesPage } from "@/pages/Policies";
import { ApiError } from "@/lib/api";
import type { PolicyDocument } from "@/api/types/PolicyDocument";
import type { PolicyDryRunResult } from "@/api/types/PolicyDryRunResult";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      policies: vi.fn(),
      savePolicy: vi.fn(),
      dryRunPolicy: vi.fn(),
    },
  };
});

// CodeMirror struggles inside happy-dom; stub it with a plain textarea so
// the UI interactions we actually care about stay observable.
vi.mock("@uiw/react-codemirror", () => ({
  default: ({
    value,
    onChange,
  }: {
    value: string;
    onChange: (v: string) => void;
  }) => (
    <textarea
      data-testid="policy-editor"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

import { api } from "@/lib/api";

const SCOPED_URL = "/policies?project=/tmp/ws-a";

function wrap(initialEntries: string[] = [SCOPED_URL]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <PoliciesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const DOC: PolicyDocument = {
  yaml: "defaults:\n  offset:\n    major: 0\n    minor: -1\n",
  from_file: true,
};

beforeEach(() => {
  (api.policies as ReturnType<typeof vi.fn>).mockReset();
  (api.savePolicy as ReturnType<typeof vi.fn>).mockReset();
  (api.dryRunPolicy as ReturnType<typeof vi.fn>).mockReset();
});

describe("PoliciesPage", () => {
  it("hydrates the editor with the on-disk YAML and marks it non-dirty", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    wrap();
    const editor = (await screen.findByTestId("policy-editor")) as HTMLTextAreaElement;
    expect(editor.value).toContain("minor: -1");
    // Buttons reflect the non-dirty state.
    expect(screen.getByRole("button", { name: /Preview impact/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /^Save$/i })).toBeDisabled();
  });

  it("enables Save + Preview once the user edits the YAML", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    wrap();
    const user = userEvent.setup();
    const editor = (await screen.findByTestId("policy-editor")) as HTMLTextAreaElement;
    await user.clear(editor);
    await user.type(editor, "defaults:\n  offset:\n    major: 0\n");
    expect(screen.getByRole("button", { name: /Preview impact/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /^Save$/i })).toBeEnabled();
    expect(screen.getByText(/unsaved/i)).toBeInTheDocument();
  });

  it("renders the dry-run counts + flipped packages when preview succeeds", async () => {
    const result: PolicyDryRunResult = {
      candidate: { compliant: 10, warnings: 3, violations: 1, insufficient: 0 },
      current: { compliant: 8, warnings: 4, violations: 2, insufficient: 0 },
      changed_packages: [
        { ecosystem: "npm", name: "lodash", from: "cve-violation", to: "warning" },
      ],
    };
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    (api.dryRunPolicy as ReturnType<typeof vi.fn>).mockResolvedValue(result);
    wrap();
    const user = userEvent.setup();
    const editor = await screen.findByTestId("policy-editor");
    await user.type(editor, " ");
    await user.click(screen.getByRole("button", { name: /Preview impact/i }));
    await waitFor(() => {
      expect(api.dryRunPolicy).toHaveBeenCalled();
    });
    expect(await screen.findByText(/First 1 flips/i)).toBeInTheDocument();
    expect(screen.getByText("lodash")).toBeInTheDocument();
  });

  it("surfaces YAML errors with line info when dry-run fails", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    (api.dryRunPolicy as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiError(
        "bad_request",
        "invalid YAML at line 3, column 5: …",
        400,
      ),
    );
    wrap();
    const user = userEvent.setup();
    const editor = await screen.findByTestId("policy-editor");
    await user.type(editor, " ");
    await user.click(screen.getByRole("button", { name: /Preview impact/i }));
    expect(
      await screen.findByText(/invalid YAML at line 3, column 5/i),
    ).toBeInTheDocument();
  });

  it("calls savePolicy with the current draft when Save is clicked", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    (api.savePolicy as ReturnType<typeof vi.fn>).mockResolvedValue({
      yaml: "defaults:\n  offset:\n    major: 0\n",
      from_file: true,
    } satisfies PolicyDocument);
    wrap();
    const user = userEvent.setup();
    const editor = (await screen.findByTestId("policy-editor")) as HTMLTextAreaElement;
    await user.clear(editor);
    await user.type(editor, "defaults:\n  offset:\n    major: 0\n");
    await user.click(screen.getByRole("button", { name: /^Save$/i }));
    await waitFor(() => {
      expect(api.savePolicy).toHaveBeenCalledWith(
        expect.stringContaining("major: 0"),
        "/tmp/ws-a",
      );
    });
  });

  it("shows the 'select a workspace' empty state when no scope is set", async () => {
    wrap(["/policies"]);
    expect(
      await screen.findByText(/Select a workspace/i),
    ).toBeInTheDocument();
    // `api.policies` must not fire without a scope — the page short-circuits
    // before the query is even enabled.
    expect(api.policies).not.toHaveBeenCalled();
  });

  it("reloads the editor when the scope flips to a different workspace", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockImplementation((project?: string) =>
      Promise.resolve({
        yaml: `# ${project ?? "none"}\ndefaults:\n  offset:\n    minor: -1\n`,
        from_file: true,
      } satisfies PolicyDocument),
    );
    wrap(["/policies?project=/tmp/ws-b"]);
    await waitFor(() => {
      expect(api.policies).toHaveBeenLastCalledWith("/tmp/ws-b");
    });
    const editor = (await screen.findByTestId("policy-editor")) as HTMLTextAreaElement;
    await waitFor(() => expect(editor.value).toContain("# /tmp/ws-b"));
  });

  it("renders hover-tooltips on the action buttons and status badges", async () => {
    (api.policies as ReturnType<typeof vi.fn>).mockResolvedValue(DOC);
    wrap();
    await screen.findByTestId("policy-editor");
    // Action buttons — each spells out exactly what it does.
    expect(
      screen.getByRole("button", { name: /Preview impact/i }).getAttribute("title"),
    ).toMatch(/candidate YAML/i);
    expect(
      screen.getByRole("button", { name: /^Save$/i }).getAttribute("title"),
    ).toMatch(/\.packguard\.yml/i);
    expect(
      screen.getByRole("button", { name: /^Revert$/i }).getAttribute("title"),
    ).toMatch(/on disk/i);
    // Status badge — "on disk" explains the hydration source.
    expect(screen.getByText(/^on disk$/i).getAttribute("title")).toMatch(
      /\.packguard\.yml/i,
    );
  });
});
