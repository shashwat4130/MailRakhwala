import React from 'react';
import {
  ShieldCheck,
  Network,
  LockKeyhole,
  Search,
  FileCheck2,
  BarChart3,
  Database,
  Cpu,
  Server,
  Layers3,
  ChevronRight,
  ExternalLink,
  BookOpen,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';

const sections = [
  {
    id: 'overview',
    title: 'Project Overview',
    icon: ShieldCheck,
    content: (
      <>
        <p>
          MailRakhwala is an email security analysis platform that works on
          captured network traffic. It reconstructs email-related traffic from
          PCAP or PCAPNG files, evaluates protocol and TLS security, identifies
          evidence-backed findings, and produces a security posture report.
        </p>
        <p className="mt-2">
          The platform is designed to turn raw packet captures into an
          understandable security assessment without requiring the user to
          inspect packets manually.
        </p>
      </>
    ),
  },
  {
    id: 'workflow',
    title: 'Analysis Workflow',
    icon: Network,
    content: (
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          ['01', 'Capture', 'Upload a PCAP or PCAPNG email traffic capture.'],
          ['02', 'Reconstruct', 'Identify streams, protocols, and email sessions.'],
          ['03', 'Evaluate', 'Inspect TLS, cryptography, protocol behaviour, and findings.'],
          ['04', 'Report', 'Generate the security posture and forensic report.'],
        ].map(([number, title, description]) => (
          <div
            key={number}
            className="rounded-xl border border-[#E5E5E0] bg-white p-4 shadow-sm"
          >
            <span className="text-xs font-mono font-bold tracking-widest text-[#111111]">
              {number}
            </span>
            <h3 className="mt-2 font-bold text-[#111111]">{title}</h3>
            <p className="mt-1.5 text-xs leading-relaxed text-[#666666]">
              {description}
            </p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: 'architecture',
    title: 'Technical Architecture',
    icon: Layers3,
    content: (
      <div className="grid gap-4 md:grid-cols-3">
        {[
          {
            icon: Network,
            title: 'PCAP Analysis Layer',
            text: 'Processes captured traffic, reconstructs streams, and classifies relevant email protocols.',
          },
          {
            icon: Cpu,
            title: 'Security Analysis Layer',
            text: 'Evaluates TLS state, cryptographic properties, protocol behaviour, and security evidence.',
          },
          {
            icon: Server,
            title: 'Application Layer',
            text: 'FastAPI services expose analysis, report, and job-status APIs to the React interface.',
          },
        ].map(({ icon: Icon, title, text }) => (
          <div
            key={title}
            className="rounded-xl border border-[#E5E5E0] bg-white p-5 shadow-sm"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#F7F7F5] border border-[#E5E5E0] text-[#111111]">
              <Icon className="h-5 w-5" />
            </div>
            <h3 className="mt-4 font-bold text-[#111111]">{title}</h3>
            <p className="mt-2 text-xs leading-relaxed text-[#666666]">
              {text}
            </p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: 'standards',
    title: 'Conformance Standards & Baselines',
    icon: LockKeyhole,
    content: (
      <div className="space-y-3">
        <p>
          MailRakhwala evaluates email sessions against authoritative Internet Engineering Task Force (IETF)
          and NIST cryptographic standards:
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-[#E5E5E0] p-3 bg-white">
            <span className="font-mono text-xs font-bold text-[#111111] block">RFC 8314</span>
            <span className="text-xs text-[#666666] block mt-1">
              Cleartext Considered Obsolete: Use of TLS for Email Submission and Access
            </span>
          </div>
          <div className="rounded-xl border border-[#E5E5E0] p-3 bg-white">
            <span className="font-mono text-xs font-bold text-[#111111] block">RFC 3207</span>
            <span className="text-xs text-[#666666] block mt-1">
              SMTP Service Extension for Secure SMTP over Transport Layer Security
            </span>
          </div>
          <div className="rounded-xl border border-[#E5E5E0] p-3 bg-white">
            <span className="font-mono text-xs font-bold text-[#111111] block">RFC 7525</span>
            <span className="text-xs text-[#666666] block mt-1">
              Recommendations for Secure Use of Transport Layer Security (TLS)
            </span>
          </div>
          <div className="rounded-xl border border-[#E5E5E0] p-3 bg-white">
            <span className="font-mono text-xs font-bold text-[#111111] block">NIST SP 800-52r2</span>
            <span className="text-xs text-[#666666] block mt-1">
              Selection, Configuration, and Use of TLS Implementations
            </span>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: 'tech-stack',
    title: 'Technology Stack',
    icon: Database,
    content: (
      <div className="overflow-hidden rounded-2xl border border-[#E5E5E0]">
        {[
          ['Frontend', 'React 19 + Vite', 'Interactive analysis console and dashboard'],
          ['UI', 'Tailwind CSS + Framer Motion', 'Responsive styling and subtle micro-interactions'],
          ['Visualizations', 'Recharts', 'Dynamic charts for severity, categories, and SHAP'],
          ['Backend', 'Python + FastAPI', 'Analysis pipelines, reports, and streaming job APIs'],
          ['Traffic Analysis', 'Scapy / dpkt / PCAP parser', 'Packet, stream, protocol, and email TLS dissection'],
          ['Reports', 'JSON + PDF (ReportLab)', 'Deterministic forensic and executive reporting'],
        ].map(([area, technology, role], index) => (
          <div
            key={area}
            className={`grid gap-1 px-4 py-3 sm:grid-cols-[140px_180px_1fr] sm:items-center text-xs ${
              index % 2 === 0 ? 'bg-white' : 'bg-[#F7F7F5]'
            }`}
          >
            <span className="font-bold uppercase tracking-wider text-[#111111]">
              {area}
            </span>
            <span className="font-semibold text-[#111111]">{technology}</span>
            <span className="text-[#666666]">{role}</span>
          </div>
        ))}
      </div>
    ),
  },
];

export default function Documentation() {
  const apiDocsUrl =
    typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
      ? 'http://127.0.0.1:8001/docs'
      : '/docs';

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <PageHeader
          category="SYSTEM"
          title="Documentation"
          description="Technical architecture, evaluation methodologies, RFC baselines, and developer API references for MailRakhwala."
        />

        {/* OpenAPI /docs Link */}
        <a
          href={apiDocsUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-[#111111] hover:bg-[#222222] text-white text-xs font-semibold shadow-sm transition-all shrink-0 self-start sm:self-auto"
        >
          <BookOpen className="h-4 w-4" />
          <span>Interactive API Docs (/docs)</span>
          <ExternalLink className="h-3.5 w-3.5 opacity-80" />
        </a>
      </div>

      <div className="grid gap-6 lg:grid-cols-[220px_1fr] lg:items-start">
        {/* Sticky Table of Contents */}
        <aside className="lg:sticky lg:top-6">
          <div className="rounded-2xl border border-[#E5E5E0] bg-white p-3 shadow-sm">
            <p className="px-3 pb-2 text-[10px] font-extrabold uppercase tracking-[0.15em] text-[#111111]">
              Table of Contents
            </p>
            <nav aria-label="Documentation sections" className="space-y-0.5">
              {sections.map(({ id, title }) => (
                <a
                  key={id}
                  href={`#${id}`}
                  className="flex items-center justify-between rounded-xl px-3 py-2 text-xs font-semibold text-[#555555] hover:bg-[#F7F7F5] hover:text-[#111111] transition-colors"
                >
                  {title}
                  <ChevronRight className="h-3.5 w-3.5 opacity-40" />
                </a>
              ))}
            </nav>

            <div className="mt-4 pt-3 border-t border-[#E5E5E0] px-3">
              <span className="text-[10px] uppercase font-bold text-[#888888] block mb-1">
                Developer API
              </span>
              <a
                href={apiDocsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-bold text-[#111111] hover:text-black"
              >
                FastAPI Swagger UI
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
        </aside>

        {/* Main Content Sections */}
        <div className="space-y-5">
          {sections.map(({ id, title, icon: Icon, content }) => (
            <section
              key={id}
              id={id}
              className="scroll-mt-6 rounded-xl border border-[#E5E5E0] bg-white p-6 shadow-sm"
            >
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#F7F7F5] border border-[#E5E5E0] text-[#111111]">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <h2 className="text-base font-bold text-[#111111]">
                    {title}
                  </h2>
                  <div className="mt-3 text-xs leading-relaxed text-[#666666]">
                    {content}
                  </div>
                </div>
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
