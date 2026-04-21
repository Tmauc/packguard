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

function wrap() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PoliciesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const DOC: PolicyDocument = {
  yaml: "defaults:\n  offset: -1\n",
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
    expect(editor.value).toContain("offset: -1");
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
    await user.type(editor, "defaults:\n  offset: 0\n");
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
      yaml: "defaults:\n  offset: 0\n",
      from_file: true,
    } satisfies PolicyDocument);
    wrap();
    const user = userEvent.setup();
    const editor = (await screen.findByTestId("policy-editor")) as HTMLTextAreaElement;
    await user.clear(editor);
    await user.type(editor, "defaults:\n  offset: 0\n");
    await user.click(screen.getByRole("button", { name: /^Save$/i }));
    await waitFor(() => {
      expect(api.savePolicy).toHaveBeenCalledWith(
        expect.stringContaining("offset: 0"),
      );
    });
  });
});
