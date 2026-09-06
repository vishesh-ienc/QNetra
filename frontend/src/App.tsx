import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { CommandCenter } from './pages/CommandCenter';
import { ScanPage } from './pages/ScanPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { CbomPage } from './pages/CbomPage';
import { RiskPage } from './pages/RiskPage';
import { QuantumPage } from './pages/QuantumPage';
import { MoscaPage } from './pages/MoscaPage';
import { MigrationPage } from './pages/MigrationPage';
import { ReportsPage } from './pages/ReportsPage';

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<CommandCenter />} />
        <Route path="scan" element={<ScanPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="cbom" element={<CbomPage />} />
        <Route path="risk" element={<RiskPage />} />
        <Route path="quantum" element={<QuantumPage />} />
        <Route path="mosca" element={<MoscaPage />} />
        <Route path="migration" element={<MigrationPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
