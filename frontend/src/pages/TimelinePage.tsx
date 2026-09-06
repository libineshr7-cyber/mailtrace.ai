// ============================================================
// MAILTRACE AI — Evidence Timeline Page (Global)
// Unified forensic evidence timeline
// ============================================================
import { useState, useEffect } from 'react';
import { Clock, Filter, Calendar } from 'lucide-react';
import TimelineTab from '../components/investigation/TimelineTab';
import { getInvestigations } from '../services/api';
import type { Investigation } from '../types';

export default function TimelinePage() {
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
      .catch((err) => console.error('Failed to load investigations for timeline', err));
  }, []);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-base sm:text-lg font-semibold text-text-primary">Evidence Timeline</h1>
          <p className="text-xs sm:text-sm text-text-muted mt-0.5">
            Strict chronological reconstruction of email ingestion, protocol parsing, and telemetry findings
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

      {/* Timeline Tab */}
      {selectedCaseId && <TimelineTab investigationId={selectedCaseId} />}
    </div>
  );
}
