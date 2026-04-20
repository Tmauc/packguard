import { useParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/// Honest placeholder for Phase 4b — wires the route + URL params so the
/// click-through from the Packages table lands somewhere meaningful, but
/// defers the 5-tab detail UI (Versions / Vulnerabilities / Malware /
/// Policy eval / Changelog) and the visx timeline to the next phase.
export function PackageDetailPage() {
  const { ecosystem, name } = useParams();
  return (
    <div className="mx-auto max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle>Package detail (Phase 4b)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-zinc-600">
          <p>
            Showing detail for{" "}
            <span className="font-mono text-zinc-900">
              {ecosystem}/{name}
            </span>
            .
          </p>
          <p>
            The 5-tab detail view (Versions / Vulnerabilities / Malware /
            Policy eval / Changelog) and the visx version timeline land in
            Phase 4b. The route + URL params are wired now so the
            click-through from the Packages table works end-to-end.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
