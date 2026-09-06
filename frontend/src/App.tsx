import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState } from 'react';
import AppShell from './components/layout/AppShell';
import LoginPage from './pages/LoginPage';
import OverviewPage from './pages/OverviewPage';
import InvestigationsPage from './pages/InvestigationsPage';
import EmailAnalysisPage from './pages/EmailAnalysisPage';
import InvestigationPage from './pages/InvestigationPage';
import IOCIntelligencePage from './pages/IOCIntelligencePage';
import InfrastructurePage from './pages/InfrastructurePage';
import GraphPage from './pages/GraphPage';
import TimelinePage from './pages/TimelinePage';
import ReportsPage from './pages/ReportsPage';
import ThreatIntelligencePage from './pages/ThreatIntelligencePage';
import AuditLogsPage from './pages/AuditLogsPage';
import SettingsPage from './pages/SettingsPage';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(
    () => sessionStorage.getItem('mailtrace_auth') === 'true'
  );

  const handleLogin = () => {
    sessionStorage.setItem('mailtrace_auth', 'true');
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    sessionStorage.removeItem('mailtrace_auth');
    setIsLoggedIn(false);
  };

  if (!isLoggedIn) {
    return (
      <BrowserRouter>
        <LoginPage onLogin={handleLogin} />
      </BrowserRouter>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="investigations" element={<InvestigationsPage />} />
          <Route path="email-analysis" element={<EmailAnalysisPage />} />
          <Route path="investigation/:id" element={<InvestigationPage />} />
          <Route path="ioc-intelligence" element={<IOCIntelligencePage />} />
          <Route path="infrastructure" element={<InfrastructurePage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="threat-intelligence" element={<ThreatIntelligencePage />} />
          <Route path="audit-logs" element={<AuditLogsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
