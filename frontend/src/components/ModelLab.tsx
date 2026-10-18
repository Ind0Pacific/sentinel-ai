"use client";

import React, { useEffect, useState } from "react";
import { Cpu, RefreshCw, BarChart2, ShieldCheck, Zap } from "lucide-react";

export default function ModelLab() {
  const [models, setModels] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchModels = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/models");
      if (res.ok) {
        const data = await res.json();
        // Fetch metrics for each model
        const enriched = await Promise.all(
          data.map(async (m: any) => {
            try {
              const mRes = await fetch(`http://127.0.0.1:8000/api/v1/models/${m.id}/metrics`);
              if (mRes.ok) {
                m.metrics = await mRes.json();
              }
            } catch (e) {}
            return m;
          })
        );
        setModels(enriched);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchModels();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Model Lab & Evaluation Registry</h2>
          <p className="text-sm text-slate-400">Actual measured benchmarks on isolated test splits with inference latencies.</p>
        </div>
        <button
          onClick={fetchModels}
          className="text-xs text-teal-400 hover:underline flex items-center space-x-1 font-mono"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono">Loading models from API...</div>
      ) : (
        <div className="space-y-5">
          {models.map((m) => {
            const metrics = m.metrics || {};
            const cm = metrics.confusion_matrix || {};
            return (
              <div
                key={m.id}
                className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-lg font-bold text-white">{m.model_name}</h3>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-700">
                        {m.status}
                      </span>
                      <span className="text-xs font-mono text-slate-400">{m.model_version}</span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono">
                      Task: {m.supported_task} | Algorithm: {m.algorithm}
                    </p>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Latency: <span className="text-teal-300 font-bold">{metrics.inference_latency_ms || "N/A"} ms</span> | Threshold: <span className="text-white">{m.decision_threshold}</span>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 font-mono">
                  <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg text-center">
                    <span className="text-xs text-slate-400 block">Precision</span>
                    <span className="text-base font-bold text-teal-400">
                      {metrics.test_precision !== undefined ? metrics.test_precision : "N/A"}
                    </span>
                  </div>
                  <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg text-center">
                    <span className="text-xs text-slate-400 block">Recall</span>
                    <span className="text-base font-bold text-blue-400">
                      {metrics.test_recall !== undefined ? metrics.test_recall : "N/A"}
                    </span>
                  </div>
                  <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg text-center">
                    <span className="text-xs text-slate-400 block">F1 Score</span>
                    <span className="text-base font-bold text-white">
                      {metrics.test_f1 !== undefined ? metrics.test_f1 : "N/A"}
                    </span>
                  </div>
                  <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg text-center">
                    <span className="text-xs text-slate-400 block">PR-AUC</span>
                    <span className="text-base font-bold text-emerald-400">
                      {metrics.test_pr_auc !== undefined ? metrics.test_pr_auc : "N/A"}
                    </span>
                  </div>
                  <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg text-center">
                    <span className="text-xs text-slate-400 block">FPR</span>
                    <span className="text-base font-bold text-emerald-400">
                      {metrics.false_positive_rate !== undefined ? metrics.false_positive_rate : "N/A"}
                    </span>
                  </div>
                </div>

                {/* Confusion Matrix */}
                {cm && (cm.true_negative !== undefined || cm.TN !== undefined) && (
                  <div className="text-xs font-mono text-slate-400 bg-[#070b14] p-3 rounded-lg border border-slate-800 flex items-center justify-around">
                    <span>TN: <b className="text-white">{cm.true_negative ?? cm.TN}</b></span>
                    <span>FP: <b className="text-red-400">{cm.false_positive ?? cm.FP}</b></span>
                    <span>FN: <b className="text-amber-400">{cm.false_negative ?? cm.FN}</b></span>
                    <span>TP: <b className="text-teal-400">{cm.true_positive ?? cm.TP}</b></span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
