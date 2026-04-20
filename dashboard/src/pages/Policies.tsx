import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";

/// Phase 4a: read-only view of the active `.packguard.yml`. Phase 4b adds
/// the form-based editor with live dry-run preview + save.
export function PoliciesPage() {
  const policy = useQuery({ queryKey: ["policies"], queryFn: api.policies });
  return (
    <div className="mx-auto max-w-3xl">
      <Card>
        <CardHeader>
          <CardTitle>Policy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {policy.isLoading ? (
            <div className="text-sm text-zinc-500">Loading…</div>
          ) : policy.error ? (
            <div className="text-sm text-red-600">
              Failed to load policy: {String(policy.error)}
            </div>
          ) : (
            <>
              <div className="flex items-center gap-2">
                {policy.data?.from_file ? (
                  <Badge tone="good">on disk</Badge>
                ) : (
                  <Badge tone="muted">conservative defaults</Badge>
                )}
                <span className="text-xs text-zinc-500">
                  Editor + dry-run preview land in Phase 4b.
                </span>
              </div>
              <pre className="overflow-auto rounded-md bg-zinc-900 p-4 text-xs text-zinc-100">
                {policy.data?.yaml}
              </pre>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
