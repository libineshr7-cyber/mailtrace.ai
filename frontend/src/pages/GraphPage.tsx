// ============================================================
// MAILTRACE AI — Investigation Graph Page (Global)
// Cross-case entity correlation & relationship graph
// ============================================================
import { useState, useEffect } from 'react';
import { GitFork, Filter, Search, Info } from 'lucide-react';
import GraphTab from '../components/investigation/GraphTab';
import { getInvestigations } from '../services/api';
import type { Investigation } from '../types';

export default function GraphPage() {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('inv-0142');

  useEffect(() => {
    getInvestigations()
      .then((invs) => {
        setInvestigations(invs);
        if (invs.length > 0) {
          setSelectedCaseId(invs[0].id);
        }
      })
      .catch((err) => console.error('Failed to load investigations for graph', err));
  }, []);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Investigation Graph</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Interactive entity relationship graph mapping email headers, domains, IPs, URLs, and file hashes
          </p>
        </div>

        {/* Case selector */}
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-text-muted shrink-0">Target Investigation:</span>
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="select text-xs py-1.5 w-full sm:w-60 font-mono"
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.caseId} ({inv.riskLevel})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Graph Component */}
      {selectedCaseId && <GraphTab investigationId={selectedCaseId} />}
    </div>
  );
}
