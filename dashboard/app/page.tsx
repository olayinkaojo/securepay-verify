"use client";

import { useCallback, useEffect, useState } from "react";

// Calls go to this app's own route handlers (app/api/*), which proxy to the
// Go API server-side and attach the API key there — the key never reaches
// the browser.

type VerifyResult = {
  risk_score: number;
  flags: string[];
  recommendation: "allow" | "review" | "block";
};

type FlaggedTransaction = {
  user_id: string;
  ip_address: string;
  country: string;
  device_fingerprint: string;
  amount: number;
  recommendation: string;
  flags: string[];
  created_at: string;
};

const recommendationStyles: Record<string, string> = {
  allow: "bg-green-100 text-green-800 border-green-300",
  review: "bg-yellow-100 text-yellow-800 border-yellow-300",
  block: "bg-red-100 text-red-800 border-red-300",
};

function RecommendationBadge({ value }: { value: string }) {
  const style =
    recommendationStyles[value] ?? "bg-gray-100 text-gray-800 border-gray-300";
  return (
    <span
      className={`inline-block rounded-full border px-3 py-0.5 text-sm font-semibold uppercase tracking-wide ${style}`}
    >
      {value}
    </span>
  );
}

function FlagBadges({ flags }: { flags: string[] }) {
  if (flags.length === 0) {
    return <span className="text-sm text-gray-400">none</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {flags.map((flag) => (
        <span
          key={flag}
          className="inline-block rounded bg-gray-200 px-2 py-0.5 font-mono text-xs text-gray-700"
        >
          {flag}
        </span>
      ))}
    </span>
  );
}

export default function Home() {
  const [form, setForm] = useState({
    user_id: "",
    ip_address: "",
    device_fingerprint: "",
    transaction_amount: "",
  });
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [flagged, setFlagged] = useState<FlaggedTransaction[]>([]);
  const [flaggedError, setFlaggedError] = useState<string | null>(null);

  const loadFlagged = useCallback(async () => {
    try {
      const res = await fetch("/api/flagged");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFlagged(await res.json());
      setFlaggedError(null);
    } catch (err) {
      setFlaggedError(
        `Could not load flagged transactions (${err}). Is the API running on :8080?`,
      );
    }
  }, []);

  useEffect(() => {
    loadFlagged();
  }, [loadFlagged]);

  const setField = (field: keyof typeof form) => (value: string) =>
    setForm((f) => ({ ...f, [field]: value }));

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: form.user_id,
          ip_address: form.ip_address,
          device_fingerprint: form.device_fingerprint,
          transaction_amount: parseFloat(form.transaction_amount),
        }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setResult(body);
      await loadFlagged();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  const fields: {
    key: keyof typeof form;
    label: string;
    placeholder: string;
    type: string;
  }[] = [
    { key: "user_id", label: "User ID", placeholder: "alice-001", type: "text" },
    { key: "ip_address", label: "IP address", placeholder: "8.8.8.8", type: "text" },
    {
      key: "device_fingerprint",
      label: "Device fingerprint",
      placeholder: "dev-alice-macbook",
      type: "text",
    },
    {
      key: "transaction_amount",
      label: "Transaction amount",
      placeholder: "55.00",
      type: "number",
    },
  ];

  return (
    <div className="min-h-screen flex-1 bg-gray-50 text-gray-900">
      <main className="mx-auto max-w-3xl px-6 py-10">
        <h1 className="text-2xl font-bold">SecurePay Verify</h1>
        <p className="mt-1 text-sm text-gray-500">
          Fraud-detection demo dashboard — proxied to the Go API via server
          routes
        </p>

        <section className="mt-8 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="text-lg font-semibold">Verify a transaction</h2>
          <form
            onSubmit={handleSubmit}
            className="mt-4 grid gap-4 sm:grid-cols-2"
          >
            {fields.map((f) => (
              <label key={f.key} className="block">
                <span className="text-sm font-medium text-gray-700">
                  {f.label}
                </span>
                <input
                  type={f.type}
                  step={f.type === "number" ? "0.01" : undefined}
                  min={f.type === "number" ? "0.01" : undefined}
                  required
                  value={form[f.key]}
                  onChange={(e) => setField(f.key)(e.target.value)}
                  placeholder={f.placeholder}
                  className="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </label>
            ))}
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 disabled:opacity-50"
              >
                {submitting ? "Verifying…" : "Verify"}
              </button>
            </div>
          </form>

          {error && (
            <p className="mt-4 rounded-md border border-red-300 bg-red-50 px-4 py-2 text-sm text-red-800">
              {error}
            </p>
          )}

          {result && (
            <div className="mt-4 flex flex-wrap items-center gap-x-8 gap-y-3 rounded-md border border-gray-200 bg-gray-50 px-4 py-3">
              <div>
                <div className="text-xs uppercase tracking-wide text-gray-500">
                  Risk score
                </div>
                <div className="text-2xl font-bold">
                  {result.risk_score}
                  <span className="text-sm font-normal text-gray-400">
                    {" "}
                    / 100
                  </span>
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-gray-500">
                  Flags
                </div>
                <div className="mt-1">
                  <FlagBadges flags={result.flags} />
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-gray-500">
                  Recommendation
                </div>
                <div className="mt-1">
                  <RecommendationBadge value={result.recommendation} />
                </div>
              </div>
            </div>
          )}
        </section>

        <section className="mt-8 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">
              Recent flagged transactions
            </h2>
            <button
              onClick={loadFlagged}
              className="rounded-md border border-gray-300 px-3 py-1 text-sm text-gray-600 hover:bg-gray-50"
            >
              Refresh
            </button>
          </div>

          {flaggedError && (
            <p className="mt-4 rounded-md border border-yellow-300 bg-yellow-50 px-4 py-2 text-sm text-yellow-800">
              {flaggedError}
            </p>
          )}

          {!flaggedError && flagged.length === 0 && (
            <p className="mt-4 text-sm text-gray-500">
              No flagged transactions yet.
            </p>
          )}

          {flagged.length > 0 && (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-xs uppercase tracking-wide text-gray-500">
                    <th className="py-2 pr-4">Time</th>
                    <th className="py-2 pr-4">User</th>
                    <th className="py-2 pr-4">IP / Country</th>
                    <th className="py-2 pr-4">Device</th>
                    <th className="py-2 pr-4 text-right">Amount</th>
                    <th className="py-2 pr-4">Flags</th>
                    <th className="py-2">Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {flagged.map((ft, i) => (
                    <tr key={i} className="border-b border-gray-100 align-top">
                      <td className="whitespace-nowrap py-2 pr-4 text-gray-500">
                        {new Date(ft.created_at).toLocaleString()}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {ft.user_id}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {ft.ip_address}
                        {ft.country && (
                          <span className="ml-1 text-gray-400">
                            ({ft.country})
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {ft.device_fingerprint}
                      </td>
                      <td className="py-2 pr-4 text-right tabular-nums">
                        {ft.amount.toFixed(2)}
                      </td>
                      <td className="py-2 pr-4">
                        <FlagBadges flags={ft.flags} />
                      </td>
                      <td className="py-2">
                        <RecommendationBadge value={ft.recommendation} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
