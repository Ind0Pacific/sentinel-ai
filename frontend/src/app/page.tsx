"use client";

import React, { useState, useEffect } from "react";
import DatasetExplorer from "../components/DatasetExplorer";
import ModelLab from "../components/ModelLab";
import PipelineMonitor from "../components/PipelineMonitor";
import { ShieldAlert, Database, Cpu, Activity, Play } from "lucide-react";

export default function Home() {
  const [activeTab, setActiveTab] = useState<"explorer" | "models" | "pipeline">("explorer");

  const triggerPipeline = async () => {
    if (confirm("Run SENTINEL AI lightweight reproducible pipeline?")) {
      try {
        const res = await fetch("http://127.0.0.1:8000/api/v1/training/jobs/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: "lightweight" }),
        });
        const data = await res.json();
        alert(`Pipeline Job Triggered: ${data.job_id}`);
        setActiveTab("pipeline");
      } catch (err: any) {
        alert(`Error triggering pipeline: ${err.message}`);
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-[#0d1527]/90 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-teal-500/10 border border-teal-500/30 text-teal-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-white flex items-center gap-2">
              SENTINEL AI <span className="text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-mono border border-blue-500/30">Next.js 14 Dashboard</span>
            </h1>
            <p className="text-xs text-slate-400">Dataset Engineering, Machine Learning Lab & Evaluation Monitor</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-full">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>API: Port 8000</span>
          </div>
          <button
            onClick={triggerPipeline}
            className="px-4 py-2 bg-teal-500/20 hover:bg-teal-500/30 text-teal-300 border border-teal-500/50 rounded-lg text-sm font-semibold flex items-center space-x-2 transition"
          >
            <Play className="w-4 h-4" />
            <span>Run Pipeline</span>
          </button>
        </div>
      </header>

      {/* Tabs */}
      <div className="border-b border-slate-800 bg-[#070b14] px-6 py-2">
        <nav className="flex space-x-2">
          <button
            onClick={() => setActiveTab("explorer")}
            className={`px-4 py-2 text-sm font-medium rounded-lg flex items-center space-x-2 transition ${
              activeTab === "explorer"
                ? "text-teal-300 bg-slate-800 border-b-2 border-teal-400"
                : "text-slate-400 hover:text-white hover:bg-slate-800/50"
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Dataset Explorer</span>
          </button>
          <button
            onClick={() => setActiveTab("models")}
            className={`px-4 py-2 text-sm font-medium rounded-lg flex items-center space-x-2 transition ${
              activeTab === "models"
                ? "text-teal-300 bg-slate-800 border-b-2 border-teal-400"
                : "text-slate-400 hover:text-white hover:bg-slate-800/50"
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Model Lab & Metrics</span>
          </button>
          <button
            onClick={() => setActiveTab("pipeline")}
            className={`px-4 py-2 text-sm font-medium rounded-lg flex items-center space-x-2 transition ${
              activeTab === "pipeline"
                ? "text-teal-300 bg-slate-800 border-b-2 border-teal-400"
                : "text-slate-400 hover:text-white hover:bg-slate-800/50"
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Pipeline Monitor</span>
          </button>
        </nav>
      </div>

      {/* Main Tab Content */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
        {activeTab === "explorer" && <DatasetExplorer />}
        {activeTab === "models" && <ModelLab />}
        {activeTab === "pipeline" && <PipelineMonitor />}
      </main>

      <footer className="border-t border-slate-800 py-4 px-6 text-center text-xs text-slate-500 font-mono">
        SENTINEL AI Next.js 14 Operations Dashboard — Real Verified Metrics | Isolated Test Benchmarks
      </footer>
    </div>
  );
}
