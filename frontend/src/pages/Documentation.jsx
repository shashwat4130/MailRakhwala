import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
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
} from 'lucide-react';

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
        <p>
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
            className="rounded-2xl border border-blue-100 bg-white p-4 shadow-sm"
          >
            <span className="text-xs font-extrabold tracking-widest text-[#0B5ED7]">
              {number}
            </span>
            <h3 className="mt-2 font-bold text-[#192837]">{title}</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-[#192837]/55">
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
            className="rounded-2xl border border-slate-200 bg-slate-50/70 p-5"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-100 text-[#0B5ED7]">
              <Icon className="h-5 w-5" />
            </div>
            <h3 className="mt-4 font-bold text-[#192837]">{title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-[#192837]/55">
              {text}
            </p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: 'security',
    title: 'Security Evaluation',
    icon: LockKeyhole,
    content: (
      <div className="grid gap-3 sm:grid-cols-2">
        {[
          ['Protocol Analysis', 'Identifies and evaluates email protocols present in the capture.'],
          ['TLS Analysis', 'Checks connection security and TLS-related observations.'],
          ['Cryptographic Review', 'Surfaces security-relevant cryptographic properties and evidence.'],
          ['Plaintext Detection', 'Identifies evidence of email traffic exposed without adequate transport protection.'],
        ].map(([title, text]) => (
          <div key={title} className="rounded-2xl border border-blue-100 bg-white p-4">
            <h3 className="font-bold text-[#192837]">{title}</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-[#192837]/55">
              {text}
            </p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: 'findings',
    title: 'Evidence & Findings',
    icon: Search,
    content: (
      <>
        <p>
          Findings are linked to observed evidence from the analyzed traffic.
          The application keeps the evidence, observed properties, and rule
          references together so that a result can be traced back to what was
          actually seen in the capture.
        </p>
        <div className="mt-4 rounded-2xl border border-blue-100 bg-blue-50/60 p-4">
          <div className="flex items-start gap-3">
            <FileCheck2 className="mt-0.5 h-5 w-5 shrink-0 text-[#0B5ED7]" />
            <div>
              <p className="font-semibold text-[#192837]">Evidence-backed reporting</p>
              <p className="mt-1 text-sm leading-relaxed text-[#192837]/55">
                Each relevant finding can be connected to the observed traffic
                property and its associated security rule.
              </p>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'posture',
    title: 'Security Posture',
    icon: BarChart3,
    content: (
      <>
        <p>
          MailRakhwala converts verified security deductions into a final
          posture score. The score starts from a base of 100, applies the
          penalties produced by the verified rules, and is constrained to the
          0–100 range.
        </p>
        <div className="mt-4 rounded-2xl border border-slate-200 bg-[#061A3A] p-5 text-white">
          <p className="text-xs font-bold uppercase tracking-[0.16em] text-cyan-200">
            Score calculation
          </p>
          <p className="mt-3 font-mono text-sm sm:text-base">
            Final Score = max(0, min(100, 100 − Total Penalty))
          </p>
          <p className="mt-2 text-xs leading-relaxed text-white/60">
            The dashboard exposes the deductions and evidence behind the final
            score so the result can be reviewed rather than treated as a black box.
          </p>
        </div>
      </>
    ),
  },
  {
    id: 'reports',
    title: 'Reports & Dashboard',
    icon: FileCheck2,
    content: (
      <div className="grid gap-3 sm:grid-cols-2">
        {[
          ['Security Dashboard', 'Summarizes the analyzed capture, posture score, and major findings.'],
          ['Score Analysis', 'Explains how the final posture score was derived from deductions.'],
          ['Full Report', 'Provides the detailed analysis view available inside the application.'],
          ['Forensic Report', 'Exports the analysis as a PDF for sharing or review.'],
        ].map(([title, text]) => (
          <div key={title} className="rounded-2xl border border-blue-100 bg-white p-4">
            <h3 className="font-bold text-[#192837]">{title}</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-[#192837]/55">
              {text}
            </p>
          </div>
        ))}
      </div>
    ),
  },
  {
    id: 'tech-stack',
    title: 'Technology Stack',
    icon: Database,
    content: (
      <div className="overflow-hidden rounded-2xl border border-blue-100">
        {[
          ['Frontend', 'React + Vite', 'Interactive analysis interface and dashboard'],
          ['UI', 'Tailwind CSS + Framer Motion', 'Responsive styling and interface animation'],
          ['Backend', 'Python + FastAPI', 'Analysis APIs, jobs, reports, and backend services'],
          ['Traffic Analysis', 'PCAP / PCAPNG processing', 'Packet, stream, protocol, and email-traffic analysis'],
          ['Reports', 'JSON + PDF', 'Machine-readable and shareable analysis output'],
        ].map(([area, technology, role], index) => (
          <div
            key={area}
            className={`grid gap-1 px-4 py-3.5 sm:grid-cols-[150px_190px_1fr] sm:items-center ${
              index % 2 === 0 ? 'bg-white' : 'bg-slate-50/70'
            }`}
          >
            <span className="text-xs font-bold uppercase tracking-wider text-[#0B5ED7]">
              {area}
            </span>
            <span className="text-sm font-semibold text-[#192837]">{technology}</span>
            <span className="text-sm text-[#192837]/55">{role}</span>
          </div>
        ))}
      </div>
    ),
  },
];

export default function Documentation() {
  const navigate = useNavigate();

  return (
    <div className="min-h-[100dvh] bg-[#f8fbff] text-[#192837]">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-[20%] -top-[20%] h-[55vh] w-[55vw] rounded-full bg-blue-300/15 blur-[130px]" />
        <div className="absolute -right-[20%] top-[8%] h-[55vh] w-[55vw] rounded-full bg-cyan-300/12 blur-[130px]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(255,255,255,0.96)_0%,rgba(255,255,255,0.9)_55%,rgba(255,255,255,0.45)_100%)]" />
      </div>

      <div className="relative z-10 mx-auto w-full max-w-[1180px] px-5 pb-12 sm:px-8">
        <header className="flex items-center justify-between gap-4 pt-5 sm:pt-7">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="inline-flex h-10 items-center gap-2 rounded-xl border border-blue-100 bg-white/90 px-3.5 text-xs font-bold text-[#192837] shadow-sm backdrop-blur-xl transition-all hover:-translate-y-0.5 hover:border-blue-200 hover:text-[#0B5ED7]"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Home
          </button>

          <div className="hidden rounded-full border border-blue-100 bg-white/80 px-4 py-2 text-[10px] font-extrabold uppercase tracking-[0.16em] text-[#0B5ED7] shadow-sm sm:block">
            Technical Documentation
          </div>
        </header>

        <section className="pt-8 text-center sm:pt-10">
          <div className="mx-auto flex h-[195px] w-[540px] max-w-full items-center justify-center sm:h-[220px] sm:w-[660px]">
            <video
              autoPlay
              muted
              loop
              playsInline
              src="/mailrakhwala-logo.mp4"
              className="h-full w-full object-contain mix-blend-multiply"
              aria-label="MailRakhwala"
            />
          </div>

          <p className="mx-auto mt-1 max-w-2xl text-sm leading-relaxed text-[#192837]/55 sm:text-base">
            Technical overview of the MailRakhwala email traffic security
            analysis platform.
          </p>
        </section>

        <div className="mt-8 grid gap-5 lg:grid-cols-[220px_1fr] lg:items-start">
          <aside className="lg:sticky lg:top-6">
            <div className="rounded-2xl border border-blue-100 bg-white/85 p-3 shadow-[0_14px_45px_rgba(15,76,160,0.08)] backdrop-blur-xl">
              <p className="px-3 pb-2 text-[10px] font-extrabold uppercase tracking-[0.15em] text-[#0B5ED7]">
                Contents
              </p>
              <nav aria-label="Documentation sections" className="space-y-0.5">
                {sections.map(({ id, title }) => (
                  <a
                    key={id}
                    href={`#${id}`}
                    className="flex items-center justify-between rounded-xl px-3 py-2 text-xs font-semibold text-[#192837]/65 transition-colors hover:bg-blue-50 hover:text-[#0B5ED7]"
                  >
                    {title}
                    <ChevronRight className="h-3.5 w-3.5 opacity-40" />
                  </a>
                ))}
              </nav>
            </div>
          </aside>

          <main className="space-y-5">
            {sections.map(({ id, title, icon: Icon, content }) => (
              <section
                key={id}
                id={id}
                className="scroll-mt-6 rounded-[24px] border border-blue-100/90 bg-white/90 p-5 shadow-[0_14px_45px_rgba(15,76,160,0.07)] backdrop-blur-xl sm:p-7"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-[#0B5ED7]">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h2 className="text-lg font-extrabold tracking-tight text-[#192837] sm:text-xl">
                      {title}
                    </h2>
                    <div className="mt-4 text-sm leading-7 text-[#192837]/65">
                      {content}
                    </div>
                  </div>
                </div>
              </section>
            ))}
          </main>
        </div>

        <footer className="mt-8 flex flex-col items-center justify-between gap-3 rounded-2xl border border-blue-100 bg-white/75 px-5 py-4 text-center shadow-sm sm:flex-row sm:text-left">
          <div>
            <p className="text-xs font-bold text-[#192837]">MailRakhwala</p>
            <p className="mt-0.5 text-[10px] text-[#192837]/45">
              Email security intelligence for captured traffic.
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate('/')}
            className="inline-flex items-center gap-1.5 text-xs font-bold text-[#0B5ED7] hover:underline"
          >
            Return to analysis
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </footer>
      </div>
    </div>
  );
}
