import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror, { EditorView } from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { toast } from "sonner";
import { FolderTreeIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { scopeLabel, useScope } from "@/components/layout/workspace-scope";
import type { PolicyDryRunResult } from "@/api/types/PolicyDryRunResult";

export function PoliciesPage() {
  const qc = useQueryClient();
  const scope = useScope();
  const policy = useQuery({
    queryKey: ["policies", scope ?? null],
    queryFn: () => api.policies(scope),
    enabled: Boolean(scope),
  });

  const [draft, setDraft] = useState<string>("");
  const [lastLoadedFromFile, setLastLoadedFromFile] = useState<boolean>(false);

  // Hydrate the editor from the server once the first read lands — and
  // reset whenever the active workspace changes, so the editor never
  // shows the previous workspace's YAML when the user flips the selector.
  useEffect(() => {
    if (policy.data) {
      setDraft(policy.data.yaml);
      setLastLoadedFromFile(policy.data.from_file);
    } else {
      setDraft("");
      setLastLoadedFromFile(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy.data?.yaml, scope]);

  const dirty = policy.data && draft !== policy.data.yaml;

  const [dryRun, setDryRun] = useState<PolicyDryRunResult | null>(null);
  const [yamlError, setYamlError] = useState<string | null>(null);

  const runDryRun = useMutation({
    mutationFn: () => api.dryRunPolicy(draft, scope),
    onSuccess: (r) => {
      setDryRun(r);
      setYamlError(null);
    },
    onError: (err: unknown) => {
      setDryRun(null);
      if (err instanceof ApiError) {
        setYamlError(err.message);
      } else {
        setYamlError(String(err));
      }
    },
  });

  const save = useMutation({
    mutationFn: () => api.savePolicy(draft, scope),
    onSuccess: (doc) => {
      setYamlError(null);
      setLastLoadedFromFile(true);
      toast.success("Policy saved", {
        description: `.packguard.yml updated on disk${scope ? ` (${scopeLabel(scope)})` : ""}.`,
      });
      qc.setQueryData(["policies", scope ?? null], doc);
      // Packages table + overview both depend on the policy — invalidate
      // the whole namespace since the scoped query key includes project.
      qc.invalidateQueries({ queryKey: ["packages"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        setYamlError(err.message);
        toast.error("Couldn't save policy", { description: err.message });
      } else {
        toast.error("Couldn't save policy", { description: String(err) });
      }
    },
  });

  const revert = () => {
    if (policy.data) {
      setDraft(policy.data.yaml);
      setDryRun(null);
      setYamlError(null);
    }
  };

  if (!scope) {
    return <SelectWorkspaceState />;
  }

  return (
    <div className="space-y-4 overflow-x-hidden">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
          Policy
        </h1>
        <ScopeBadge />
        {lastLoadedFromFile ? (
          <Badge
            tone="good"
            title="Editor is hydrated from the workspace's .packguard.yml on disk."
          >
            on disk
          </Badge>
        ) : (
          <Badge
            tone="muted"
            title="No .packguard.yml found — showing PackGuard's conservative defaults. Save to create the file."
          >
            conservative defaults
          </Badge>
        )}
        {dirty && (
          <Badge
            tone="warn"
            title="Editor has unsaved changes relative to what's on disk."
          >
            unsaved
          </Badge>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => runDryRun.mutate()}
            disabled={runDryRun.isPending || !dirty}
            title="Evaluate the candidate YAML against the last scan and show how buckets (compliant/warning/violation/insufficient) would shift. Nothing is persisted."
          >
            {runDryRun.isPending ? "Previewing…" : "Preview impact"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={revert}
            disabled={!dirty || save.isPending}
            title="Discard editor changes and reload the YAML currently on disk."
          >
            Revert
          </Button>
          <Button
            size="sm"
            onClick={() => save.mutate()}
            disabled={!dirty || save.isPending}
            title="Atomically write the candidate YAML to .packguard.yml (write + rename). CLI and dashboard will pick up the new policy on the next evaluation."
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </header>

      <div
        className="grid gap-4 min-[1200px]:grid-cols-[1fr_22rem]"
        data-testid="policies-grid"
      >
        <Card>
          <CardHeader>
            <CardTitle>.packguard.yml</CardTitle>
          </CardHeader>
          <CardContent>
            {policy.isLoading ? (
              <div className="text-sm text-zinc-500 dark:text-zinc-400">Loading…</div>
            ) : policy.error ? (
              <div className="text-sm text-red-600 dark:text-red-400">
                Failed to load: {String(policy.error)}
              </div>
            ) : (
              <CodeMirror
                value={draft}
                height="420px"
                extensions={[yamlLang(), EditorView.lineWrapping]}
                onChange={(v) => setDraft(v)}
                basicSetup={{
                  lineNumbers: true,
                  foldGutter: false,
                  highlightActiveLine: true,
                }}
                data-testid="policy-editor"
              />
            )}
            {yamlError && (
              <pre className="mt-3 whitespace-pre-wrap rounded-md border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-3 text-xs text-red-700 dark:text-red-300">
                {yamlError}
              </pre>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <DryRunCard result={dryRun} loading={runDryRun.isPending} />
          <HelpCard />
        </div>
      </div>
    </div>
  );
}

function DryRunCard({
  result,
  loading,
}: {
  result: PolicyDryRunResult | null;
  loading: boolean;
}) {
  const deltas = useMemo(() => {
    if (!result) return [];
    const k: (keyof typeof result.candidate)[] = [
      "compliant",
      "warnings",
      "violations",
      "insufficient",
    ];
    return k.map((key) => ({
      label: key,
      current: result.current[key],
      candidate: result.candidate[key],
      delta: result.candidate[key] - result.current[key],
    }));
  }, [result]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Dry-run impact</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="text-sm text-zinc-500 dark:text-zinc-400">Evaluating candidate…</div>
        ) : !result ? (
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            Edit the YAML and click <span className="font-medium">Preview impact</span>{" "}
            to see how the candidate policy would re-bucket your packages
            against the last scan. Nothing is persisted until you hit Save.
          </p>
        ) : (
          <>
            <table className="w-full text-xs">
              <thead className="text-zinc-500 dark:text-zinc-400">
                <tr>
                  <th className="text-left font-medium">Bucket</th>
                  <th
                    className="text-right font-medium"
                    title="Current bucket count under the policy on disk."
                  >
                    Now
                  </th>
                  <th
                    className="text-right font-medium"
                    title="Bucket count if the candidate YAML in the editor were saved."
                  >
                    Candidate
                  </th>
                  <th
                    className="text-right font-medium"
                    title="Candidate minus Now. Red = more packages fell into that bucket; green = fewer."
                  >
                    Δ
                  </th>
                </tr>
              </thead>
              <tbody>
                {deltas.map((d) => (
                  <tr key={d.label} className="border-t border-zinc-100 dark:border-zinc-800">
                    <td className="py-1 capitalize">{d.label}</td>
                    <td className="py-1 text-right font-mono">{d.current}</td>
                    <td className="py-1 text-right font-mono">{d.candidate}</td>
                    <td
                      className={`py-1 text-right font-mono ${
                        d.delta === 0
                          ? "text-zinc-500 dark:text-zinc-400"
                          : d.delta > 0
                            ? "text-red-600 dark:text-red-400"
                            : "text-emerald-600 dark:text-emerald-400"
                      }`}
                      title={
                        d.delta === 0
                          ? `No change in the ${d.label} bucket.`
                          : d.delta > 0
                            ? `${d.delta} more package(s) would fall into the ${d.label} bucket under the candidate policy.`
                            : `${-d.delta} fewer package(s) would be in the ${d.label} bucket under the candidate policy.`
                      }
                    >
                      {d.delta > 0 ? `+${d.delta}` : d.delta}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {result.changed_packages.length > 0 && (
              <div className="mt-3">
                <div
                  className="mb-1 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400"
                  title="Individual packages whose compliance verdict would change under the candidate policy, evaluated against the last scan."
                >
                  First {result.changed_packages.length} flips
                </div>
                <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">
                  {result.changed_packages.map((c) => (
                    <li
                      key={`${c.ecosystem}/${c.name}`}
                      className="rounded border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-2 py-1"
                      title={`${c.name} (${c.ecosystem}) would flip from "${c.from}" to "${c.to}" if you saved the candidate policy.`}
                    >
                      <span className="font-mono">{c.name}</span>{" "}
                      <span className="text-zinc-500 dark:text-zinc-400">({c.ecosystem})</span>
                      <span className="ml-1 text-zinc-500 dark:text-zinc-400">
                        {c.from} → <span className="text-zinc-900 dark:text-zinc-100">{c.to}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function SelectWorkspaceState() {
  return (
    <div className="space-y-4 overflow-x-hidden">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
          Policy
        </h1>
        <ScopeBadge />
      </header>
      <Card>
        <CardHeader>
          <CardTitle>Select a workspace</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-zinc-600 dark:text-zinc-400">
          <div className="flex items-start gap-3">
            <FolderTreeIcon className="mt-0.5 h-5 w-5 flex-shrink-0 text-zinc-400 dark:text-zinc-500" />
            <div className="space-y-2">
              <p>
                Each workspace owns its own{" "}
                <span className="font-mono">.packguard.yml</span>. Pick one from
                the <span className="font-medium">Workspace</span> dropdown in
                the header to load its policy.
              </p>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                If you haven&apos;t scanned anything yet, run{" "}
                <span className="font-mono">packguard scan &lt;path&gt;</span>{" "}
                first — the workspace will appear automatically.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function HelpCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Reference</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs text-zinc-600 dark:text-zinc-400">
        <p>
          The policy language reference lives in{" "}
          <a
            className="underline"
            href="https://github.com/nalo/packguard#policy-format"
            target="_blank"
            rel="noreferrer"
          >
            CONTEXT.md §6
          </a>
          . Blocks: <code>defaults</code>, <code>overrides</code>,{" "}
          <code>groups</code>, and <code>block</code>.
        </p>
        <p>
          Saves land in{" "}
          <span className="font-mono">&lt;repo&gt;/.packguard.yml</span> atomically
          (write + rename). Commit the file to git so the CLI and CI match.
        </p>
      </CardContent>
    </Card>
  );
}
