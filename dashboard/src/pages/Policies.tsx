import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import type { PolicyDryRunResult } from "@/api/types/PolicyDryRunResult";

export function PoliciesPage() {
  const qc = useQueryClient();
  const policy = useQuery({ queryKey: ["policies"], queryFn: api.policies });

  const [draft, setDraft] = useState<string>("");
  const [lastLoadedFromFile, setLastLoadedFromFile] = useState<boolean>(false);

  // Hydrate the editor from the server once the first read lands.
  useEffect(() => {
    if (policy.data && draft === "") {
      setDraft(policy.data.yaml);
      setLastLoadedFromFile(policy.data.from_file);
    }
    // Deliberate: we only hydrate on first load; afterwards the user's edits
    // are the source of truth until they Save / Revert.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy.data?.yaml]);

  const dirty = policy.data && draft !== policy.data.yaml;

  const [dryRun, setDryRun] = useState<PolicyDryRunResult | null>(null);
  const [yamlError, setYamlError] = useState<string | null>(null);

  const runDryRun = useMutation({
    mutationFn: () => api.dryRunPolicy(draft),
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
    mutationFn: () => api.savePolicy(draft),
    onSuccess: (doc) => {
      setYamlError(null);
      setLastLoadedFromFile(true);
      toast.success("Policy saved", {
        description: ".packguard.yml updated on disk.",
      });
      qc.setQueryData(["policies"], doc);
      // Packages table + overview both depend on the policy — invalidate.
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

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900">
          Policy
        </h1>
        {lastLoadedFromFile ? (
          <Badge tone="good">on disk</Badge>
        ) : (
          <Badge tone="muted">conservative defaults</Badge>
        )}
        {dirty && <Badge tone="warn">unsaved</Badge>}
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => runDryRun.mutate()}
            disabled={runDryRun.isPending || !dirty}
          >
            {runDryRun.isPending ? "Previewing…" : "Preview impact"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={revert}
            disabled={!dirty || save.isPending}
          >
            Revert
          </Button>
          <Button
            size="sm"
            onClick={() => save.mutate()}
            disabled={!dirty || save.isPending}
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <Card>
          <CardHeader>
            <CardTitle>.packguard.yml</CardTitle>
          </CardHeader>
          <CardContent>
            {policy.isLoading ? (
              <div className="text-sm text-zinc-500">Loading…</div>
            ) : policy.error ? (
              <div className="text-sm text-red-600">
                Failed to load: {String(policy.error)}
              </div>
            ) : (
              <CodeMirror
                value={draft}
                height="420px"
                extensions={[yamlLang()]}
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
              <pre className="mt-3 whitespace-pre-wrap rounded-md border border-red-200 bg-red-50 p-3 text-xs text-red-700">
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
          <div className="text-sm text-zinc-500">Evaluating candidate…</div>
        ) : !result ? (
          <p className="text-xs text-zinc-500">
            Edit the YAML and click <span className="font-medium">Preview impact</span>{" "}
            to see how the candidate policy would re-bucket your packages
            against the last scan. Nothing is persisted until you hit Save.
          </p>
        ) : (
          <>
            <table className="w-full text-xs">
              <thead className="text-zinc-500">
                <tr>
                  <th className="text-left font-medium">Bucket</th>
                  <th className="text-right font-medium">Now</th>
                  <th className="text-right font-medium">Candidate</th>
                  <th className="text-right font-medium">Δ</th>
                </tr>
              </thead>
              <tbody>
                {deltas.map((d) => (
                  <tr key={d.label} className="border-t border-zinc-100">
                    <td className="py-1 capitalize">{d.label}</td>
                    <td className="py-1 text-right font-mono">{d.current}</td>
                    <td className="py-1 text-right font-mono">{d.candidate}</td>
                    <td
                      className={`py-1 text-right font-mono ${
                        d.delta === 0
                          ? "text-zinc-500"
                          : d.delta > 0
                            ? "text-red-600"
                            : "text-emerald-600"
                      }`}
                    >
                      {d.delta > 0 ? `+${d.delta}` : d.delta}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {result.changed_packages.length > 0 && (
              <div className="mt-3">
                <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">
                  First {result.changed_packages.length} flips
                </div>
                <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">
                  {result.changed_packages.map((c) => (
                    <li
                      key={`${c.ecosystem}/${c.name}`}
                      className="rounded border border-zinc-200 bg-white px-2 py-1"
                    >
                      <span className="font-mono">{c.name}</span>{" "}
                      <span className="text-zinc-500">({c.ecosystem})</span>
                      <span className="ml-1 text-zinc-500">
                        {c.from} → <span className="text-zinc-900">{c.to}</span>
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

function HelpCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Reference</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs text-zinc-600">
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
