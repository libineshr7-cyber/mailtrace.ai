// ============================================================
// MAILTRACE AI — Login Page
// Professional minimal security product login screen
// ============================================================
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, Eye, EyeOff } from 'lucide-react';

interface Props {
  onLogin?: () => void;
}

export default function LoginPage({ onLogin }: Props) {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIsLoading(true);
    // Simulate auth handshake delay then navigate
    setTimeout(() => {
      setIsLoading(false);
      if (onLogin) {
        onLogin();
      } else {
        navigate('/');
      }
    }, 600);
  }

  return (
    <div className="min-h-screen w-full bg-bg-primary flex flex-col items-center justify-center px-4">
      {/* Login card */}
      <div className="w-full max-w-sm bg-bg-secondary border border-border rounded p-8">

        {/* Brand header */}
        <div className="flex flex-col items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-accent-blue rounded flex items-center justify-center flex-shrink-0">
            <Shield size={20} className="text-white" strokeWidth={2} />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold text-text-primary tracking-tight">
              MAILTRACE{' '}
              <span className="text-accent-blue">AI</span>
            </h1>
            <p className="text-2xs text-text-muted mt-1 leading-relaxed">
              AI-Powered Email Threat Detection &amp; Forensic Intelligence
            </p>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-border mb-6" />

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">

          {/* Email field */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="email" className="text-xs font-medium text-text-secondary">
              Email address
            </label>
            <div className="relative">
              <Mail
                size={14}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none"
              />
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="analyst@company.internal"
                className="input pl-9 text-sm"
              />
            </div>
          </div>

          {/* Password field */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="password" className="text-xs font-medium text-text-secondary">
              Password
            </label>
            <div className="relative">
              <Lock
                size={14}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none"
              />
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                className="input pl-9 pr-9 text-sm"
              />
              <button
                type="button"
                onClick={() => setShowPassword(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword
                  ? <EyeOff size={14} />
                  : <Eye size={14} />
                }
              </button>
            </div>
          </div>

          {/* Keep signed in */}
          <label className="flex items-center gap-2.5 cursor-pointer select-none mt-1">
            <input
              type="checkbox"
              checked={keepSignedIn}
              onChange={e => setKeepSignedIn(e.target.checked)}
              className="w-3.5 h-3.5 rounded-sm border border-border bg-bg-tertiary accent-accent-blue cursor-pointer"
            />
            <span className="text-xs text-text-secondary">Keep me signed in</span>
          </label>

          {/* Submit */}
          <button
            type="submit"
            disabled={isLoading}
            className="btn-primary w-full justify-center mt-1 py-2 text-sm disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Authenticating...
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>
      </div>

      {/* Footer */}
      <p className="mt-5 text-2xs text-text-muted select-none">
        Secure authentication · MAILTRACE AI v1.0.0
      </p>
    </div>
  );
}
