// ============================================================
// MAILTRACE AI — Loading, Empty & Error States
// ============================================================
import { AlertTriangle, FileX, Loader2, ServerOff } from 'lucide-react';

export function LoadingSpinner({ size = 16, className = '' }: { size?: number; className?: string }) {
  return <Loader2 size={size} className={`animate-spin text-text-muted ${className}`} />;
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`bg-bg-tertiary animate-pulse rounded ${className}`} />;
}

export function TableSkeleton({ rows = 5, cols = 6 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-px">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-4 px-4 py-3 bg-bg-secondary border-b border-border">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className={`h-3 ${c === 0 ? 'w-32' : c === 1 ? 'w-20' : 'w-16'} flex-shrink-0`} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function CardSkeleton({ className = '' }: { className?: string }) {
  return (
    <div className={`panel p-4 space-y-3 ${className}`}>
      <Skeleton className="h-3 w-24" />
      <Skeleton className="h-6 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  );
}

export function EmptyState({
  title = 'No data',
  description = 'Nothing to display',
  icon: Icon = FileX,
}: {
  title?: string;
  description?: string;
  icon?: React.ComponentType<{ size?: number; className?: string }>;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      <Icon size={32} className="text-text-muted" />
      <div>
        <p className="text-sm font-medium text-text-secondary">{title}</p>
        <p className="text-xs text-text-muted mt-0.5">{description}</p>
      </div>
    </div>
  );
}

export function ErrorState({
  message = 'An error occurred',
  retry,
}: {
  message?: string;
  retry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      <ServerOff size={32} className="text-critical" />
      <div>
        <p className="text-sm font-medium text-text-secondary">Error loading data</p>
        <p className="text-xs text-text-muted mt-0.5">{message}</p>
      </div>
      {retry && (
        <button onClick={retry} className="btn-secondary text-xs mt-2">
          Retry
        </button>
      )}
    </div>
  );
}

export function InlineError({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 bg-critical-muted border border-critical-border rounded text-critical text-xs">
      <AlertTriangle size={12} />
      <span>{message}</span>
    </div>
  );
}

export function LoadingOverlay({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3">
      <LoadingSpinner size={24} />
      <p className="text-xs text-text-muted">{message}</p>
    </div>
  );
}
