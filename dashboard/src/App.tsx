import { Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { OverviewPage } from "@/pages/Overview";
import { PackagesPage } from "@/pages/Packages";
import { PackageDetailPage } from "@/pages/PackageDetail";
import { PoliciesPage } from "@/pages/Policies";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="packages" element={<PackagesPage />} />
        <Route
          path="packages/:ecosystem/:name"
          element={<PackageDetailPage />}
        />
        <Route path="policies" element={<PoliciesPage />} />
      </Route>
    </Routes>
  );
}
