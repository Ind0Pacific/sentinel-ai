"use client";

import React, { useEffect, useState } from "react";
import { Activity, RefreshCw, CheckCircle2, XCircle, Clock } from "lucide-react";

export default function PipelineMonitor() {
  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchJobs = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/training/jobs");
      if (res.ok) {
        const data = await res.json();
        setJobs(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchJobs();
    const interval = setInterval(fetchJobs, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Pipeline Monitor</h2>
          <p className="text-sm text-slate-400">Real-time status of dataset ingestion, preprocessing, training, and benchmarking.</p>
        </div>
        <button
          onClick={fetchJobs}
          className="text-xs text-teal-400 hover:underline flex items-center space-x-1 font-mono"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {loading && jobs.length === 0 ? (
        <div className="p-12 text-center text-slate-500 font-mono">Fetching pipeline executions...</div>
      ) : jobs.length === 0 ? (
        <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
          No pipeline runs recorded yet. Use the "Run Pipeline" button above to initiate one.
        </div>
      ) : (
        <div className="space-y-4">
          {jobs.map((j) => (
            <div
              key={j.job_id}
              className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white">{j.job_id}</span>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded border ${
                    j.status === "SUCCESS"
                      ? "bg-emerald-950 text-emerald-400 border-emerald-700"
                      : j.status === "RUNNING"
                      ? "bg-blue-950 text-blue-400 border-blue-700 animate-pulse"
                      : "bg-red-950 text-red-400 border-red-700"
                  }`}
                >
                  {j.status}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Mode: {j.mode} | Duration: {j.duration_seconds || 0}s | Completed: {j.completed_at || j.started_at}
              </p>

              {j.stages && j.stages.length > 0 && (
                <div className="space-y-1.5 pt-3 border-t border-slate-800">
                  {j.stages.map((stg: any, idx: number) => (
                    <div
                      key={idx}
                      className="text-xs flex items-center justify-between text-slate-300"
                    >
                      <span className="flex items-center space-x-2">
                        {stg.status === "COMPLETED" ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-red-400" />
                        )}
                        <span>{stg.stage}</span>
                      </span>
                      <span className="text-slate-500">{stg.duration_seconds}s</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
