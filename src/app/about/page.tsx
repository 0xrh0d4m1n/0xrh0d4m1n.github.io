import type { Metadata } from "next";
import Image from "next/image";
import { MapPin, Link2, Users, ShieldCheck } from "lucide-react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { icons } from "@/lib/icons";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { CertificationsSection } from "@/components/skills/certifications-section";
import type {
  CertCompanyGroup,
  ExperienceItem,
  SkillCategory,
  EducationRow,
  ProjectItem,
  AchievementItem,
  LanguageItem,
  ResumeLink,
} from "@/types/profile";

export const metadata: Metadata = { title: "About" };

/* ────────────────────────────────────────────────────────────────── */
/*  Static profile data                                              */
/* ────────────────────────────────────────────────────────────────── */

const PROFILE = {
  name: "Valdênio Marinho (0xrh0d4m1n)",
  headline:
    "Cyber Security Architect | SOC | CSIRT | DFIR | CTI | Instructor",
  location: "Remote — Worldwide",
  website: "https://www.linkedin.com/in/0xrh0d4m1n/",
  connections: "500+",
  avatar: "/img/profile/me.jpg",
  banner: "/img/hero/b0740b2a8afc9453749b5e013a2db6fb.png",
  currentCompany: {
    name: "Akamai Technologies",
    logo: "/img/companies/akamai.jpg",
  },
} as const;

const ABOUT_TEXT = "Cybersecurity professional with roots in Full Stack Web Development and Electrical Engineering. Started with electronics and microcontrollers, transitioned into Web Dev with the help of great mentors, moved to explore Blockchain Technologies, and then found a true calling in Cybersecurity where has been working in this field for years until these days. Completed many top-tier training, also practiced extensively in advanced scenarios of the cyber realm covering the full spectrum of Defense/Offensive techniques and strategies. Additionaly practices Bug Bounty in worldwide. Currently is specialized in Application, Microservices and API Protection with a deep understanding in DDoS mitigation and network-based threat defense (L3/4/7), working with WAFs, SIEM, SOAR, and IDS/IPS. Also deeply engaged in Cyber Threat Intelligence, Threat Modeling, Threat Hunting, Reverse Engineering, and Malware Analysis — to anticipate APT tactics and strengthen countermeasures. Driven by continuous learning and a healthy respect for how much there is still to learn.";

const EXPERIENCE: ExperienceItem[] = [
  {
    role: "Cyber Security Architect - SOC",
    company: "Akamai Technologies",
    logo: "/img/companies/akamai.jpg",
    location: "Massachusetts, United States — Remote",
    dates: "Dec 2025 — Present",
    bullets: [
      "Engaged in technical integration of security solutions, configuration, validation, troubleshooting.",
      "Analyze traffic patterns and security events to identify risks and tailor protective controls.",
      "Design security architectures, transforming compliance requirements into actionable frameworks.",
      "Collaborate with cross-functional teams on scope, timelines, success criteria, and execution plans",
      "Guide customers through deployment, optimization, and security posture improvements.",
      "Develop and share knowledge via internal training, best practices, and team enablement.",
    ],
  },
  {
    role: "SOC Analyst",
    company: "Nexusguard",
    logo: "/img/companies/nexusguard.jpg",
    location: "Singapore — Remote",
    dates: "2024 — Present",
    bullets: [
      "Monitor and analyze security events using SIEM tools to detect, investigate, and respond to threats.",
      "Collaborate with incident response teams to mitigate risks and contain security incidents.",
      "Analyze alerts to identify threat patterns, enhancing detection and response capabilities.",
      "Generate detailed reports and presentations on threat intelligence findings.",
      "Leverage Nexusguard's DDoS mitigation tech against volumetric, protocol, and application-layer attacks.",
    ],
  },
  {
    role: "Cybersecurity Researcher",
    company: "HackerOne",
    logo: "/img/companies/hackerone.jpg",
    location: "San Francisco, California, United States — Remote",
    dates: "2023 — Present",
    bullets: [
      "Successfully identified and reported a significant security vulnerability through HackerOne's Bug Bounty Program.",
      "Utilized advanced security testing platforms to perform comprehensive vulnerability assessments.",
      "Analyzed and reported findings from vulnerability discovery tools to provide actionable insights.",
      "Collaborated with cross-functional teams to address identified vulnerabilities.",
    ],
  },
  {
    role: "Fullstack Web Developer",
    company: "Freelancing",
    logo: "/img/companies/freelancer.jpg",
    location: "Worldwide — Remote",
    dates: "2018 — 2022",
    bullets: [
      "Designed and developed scalable, high-performance web applications.",
      "Managed software development lifecycle from initial planning and design to deployment and maintenance.",
      "Integrated third-party APIs and services to enhance application functionality.",
      "Conducted thorough testing and debugging to ensure optimal performance.",
    ],
  },
];

const SKILLS: SkillCategory[] = [
  {
    title: "Security & Operations",
    badges: [
      /* ── Blue / Defensive ──────────────────────────────────────── */
      { label: "Blue Team", src: "https://img.shields.io/badge/-Blue%20Team-1e3a8a?logo=shieldsdotio&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Cyber Threat Intelligence", src: "https://img.shields.io/badge/-Cyber%20Threat%20Intelligence-7b2d8e?logo=virustotal&logoColor=00f0ff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Incident Response", src: "https://img.shields.io/badge/-Incident%20Response-b91c1c?logo=statuspage&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "SOC", src: "https://img.shields.io/badge/-SOC-0f766e?logo=parrotsecurity&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "SIEM", src: "https://img.shields.io/badge/-SIEM-0369a1?logo=googlechronicle&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "NOC", src: "https://img.shields.io/badge/-NOC-1e40af?logo=junipernetworks&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Malware Analysis", src: "https://img.shields.io/badge/-Malware%20Analysis-581c87?logo=malwarebytes&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Digital Forensics", src: "https://img.shields.io/badge/-Digital%20Forensics-0c4a6e?logo=googlechronicle&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Information Security", src: "https://img.shields.io/badge/-Information%20Security-047857?logo=keybase&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Network Security", src: "https://img.shields.io/badge/-Network%20Security-155e75?logo=paloaltonetworks&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Vulnerability Assessment", src: "https://img.shields.io/badge/-Vulnerability%20Assessment-d97706?logo=openbugbounty&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Web App Security", src: "https://img.shields.io/badge/-Web%20App%20Security-374151?logo=owasp&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "GRC", src: "https://img.shields.io/badge/-GRC-b45309?logo=dependencycheck&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Risk Management", src: "https://img.shields.io/badge/-Risk%20Management-b45309?logo=securityscorecard&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Cryptography", src: "https://img.shields.io/badge/-Cryptography-5b21b6?logo=cryptomator&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      /* ── Red / Offensive ───────────────────────────────────────── */
      { label: "Penetration Testing", src: "https://img.shields.io/badge/-Penetration%20Testing-7f1d1d?logo=target&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Red Team", src: "https://img.shields.io/badge/-Red%20Team-991b1b?logo=hackthebox&logoColor=9FEF00&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Ethical Hacking", src: "https://img.shields.io/badge/-Ethical%20Hacking-b91c1c?logo=kalilinux&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Bug Bounty", src: "https://img.shields.io/badge/-Bug%20Bounty-9a3412?logo=bugcrowd&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Recon", src: "https://img.shields.io/badge/-Recon-4c1d95?logo=radar&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
    ],
  },
  {
    title: "Programming & Stack",
    badges: [
      { label: "JavaScript", src: "https://img.shields.io/badge/-JavaScript-a16207?logo=javascript&logoColor=F7DF1E&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "TypeScript", src: "https://img.shields.io/badge/-TypeScript-1e40af?logo=typescript&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Python", src: "https://img.shields.io/badge/-Python-1e3a5f?logo=python&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Node.js", src: "https://img.shields.io/badge/-Node.js-166534?logo=nodedotjs&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Go", src: "https://img.shields.io/badge/-Go-0d9488?logo=go&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Nim", src: "https://img.shields.io/badge/-Nim-92400e?logo=nim&logoColor=FFE000&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Rust", src: "https://img.shields.io/badge/-Rust-1c1917?logo=rust&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Shell Script", src: "https://img.shields.io/badge/-Shell%20Script-14532d?logo=gnubash&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "React", src: "https://img.shields.io/badge/-React-0c4a6e?logo=react&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Next.js", src: "https://img.shields.io/badge/-Next.js-1c1917?logo=nextdotjs&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Express.js", src: "https://img.shields.io/badge/-Express.js-374151?logo=express&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "GraphQL", src: "https://img.shields.io/badge/-GraphQL-e11d48?logo=graphql&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Redux", src: "https://img.shields.io/badge/-Redux-5b21b6?logo=redux&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Assembly", src: "https://img.shields.io/badge/-Assembly-0c4a6e?logo=intel&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
    ],
  },
  {
    title: "Tools & Technologies",
    badges: [
      { label: "Burp Suite", src: "https://img.shields.io/badge/-Burp%20Suite-c2410c?logo=burpsuite&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "OWASP ZAP", src: "https://img.shields.io/badge/-OWASP%20ZAP-374151?logo=owasp&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Kali Linux", src: "https://img.shields.io/badge/-Kali%20Linux-557c3b?logo=kalilinux&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "OpenVAS", src: "https://img.shields.io/badge/-OpenVAS-14532d?logo=scan&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Tenable Nessus", src: "https://img.shields.io/badge/-Tenable%20Nessus-0369a1?logo=securityscorecard&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Metasploit", src: "https://img.shields.io/badge/-Metasploit-155e75?logo=metasploit&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Nmap", src: "https://img.shields.io/badge/-Nmap-991b1b?logo=junipernetworks&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Wireshark", src: "https://img.shields.io/badge/-Wireshark-1e40af?logo=wireshark&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Splunk", src: "https://img.shields.io/badge/-Splunk-0f766e?logo=splunk&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Elastic", src: "https://img.shields.io/badge/-Elastic-1e3a5f?logo=elastic&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Snort", src: "https://img.shields.io/badge/-Snort-7f1d1d?logo=snort&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Ghidra", src: "https://img.shields.io/badge/-Ghidra-0e7490?logo=eclipseide&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Docker", src: "https://img.shields.io/badge/-Docker-0284c7?logo=docker&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Kubernetes", src: "https://img.shields.io/badge/-Kubernetes-326ce5?logo=kubernetes&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Ansible", src: "https://img.shields.io/badge/-Ansible-1c1917?logo=ansible&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Cloudflare", src: "https://img.shields.io/badge/-Cloudflare-c2410c?logo=cloudflare&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Fortinet", src: "https://img.shields.io/badge/-Fortinet-0f766e?logo=fortinet&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Palo Alto", src: "https://img.shields.io/badge/-Palo%20Alto-1e40af?logo=paloaltonetworks&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Cisco", src: "https://img.shields.io/badge/-Cisco-0d9488?logo=cisco&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "F5", src: "https://img.shields.io/badge/-F5-374151?logo=f5&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Grafana", src: "https://img.shields.io/badge/-Grafana-b45309?logo=grafana&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "MongoDB", src: "https://img.shields.io/badge/-MongoDB-047857?logo=mongodb&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "MySQL", src: "https://img.shields.io/badge/-MySQL-0c4a6e?logo=mysql&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Redis", src: "https://img.shields.io/badge/-Redis-dc2626?logo=redis&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
      { label: "Git", src: "https://img.shields.io/badge/-Git-374151?logo=git&logoColor=ffffff&style=for-the-badge&logoWidth=28&labelColor=1f2937" },
    ],
  },
];

const CERTIFICATIONS: CertCompanyGroup[] = [
  {
    company: "Fortinet",
    logo: "/img/companies/fortinet.jpg",
    certs: [
      { title: "Fortinet Cybersecurity Associate", src: "/img/certs/fortinet-fca.png" },
      { title: "Fortinet Cybersecurity Fundamentals", src: "/img/certs/fortinet-fcf.png" },
      { title: "Fortinet Network Security Level 3", src: "/img/certs/fortinet-network-sec-level-3.png" },
      { title: "Fortinet Network Security Level 2", src: "/img/certs/fortinet-network-sec-level-2.png" },
      { title: "Fortinet Network Security Level 1", src: "/img/certs/fortinet-network-sec-level-1.png" },
    ],
  },
  {
    company: "Google",
    logo: "/img/companies/google.jpg",
    certs: [
      { title: "Google Cyber Professional", src: "/img/certs/google-cyber-0.png" },
      { title: "Foundations of Cybersecurity", src: "/img/certs/google-cyber-1.png" },
      { title: "Manage Security Risks", src: "/img/certs/google-cyber-2.png" },
      { title: "Networks and Network Security", src: "/img/certs/google-cyber-3.png" },
      { title: "Linux and SQL", src: "/img/certs/google-cyber-4.png" },
      { title: "Assets Threats Vulnerabilities", src: "/img/certs/google-cyber-5.png" },
      { title: "Detection and Response", src: "/img/certs/google-cyber-6.png" },
      { title: "Cybersecurity Tasks with Python", src: "/img/certs/google-cyber-7.png" },
      { title: "Preparation for Cybersecurity Jobs", src: "/img/certs/google-cyber-8.png" },
    ],
  },
  {
    company: "Cybrary",
    logo: "/img/companies/cybrary.jpg",
    certs: [
      { title: "Offensive Penetration Testing", src: "/img/certs/cybrary-offensive-pentest.png" },
      { title: "Advanced Penetration Testing", src: "/img/certs/cybrary-advanced-pentest.png" },
      { title: "Penetration Testing", src: "/img/certs/cybrary-become-pentester.png" },
      { title: "Penetration Testing & Ethical Hacking", src: "/img/certs/cybrary-pentest-ethical-hacking.png" },
      { title: "OWASP TOP 10", src: "/img/certs/cybrary-owasp-top10.png" },
      { title: "CompTIA Security+", src: "/img/certs/cybrary-comptia-security.png" },
      { title: "Cyber Kill Chain Framework", src: "/img/certs/cybrary-cyber-kill-chain.png" },
      { title: "MITRE ATT&CK Framework", src: "/img/certs/cybrary-mitre-framework.png" },
      { title: "Security Operations Analyst (SOC)", src: "/img/certs/cybrary-become-soc-1.png" },
      { title: "CompTIA Linux+", src: "/img/certs/cybrary-comptia-linux.png" },
      { title: "System Administrator", src: "/img/certs/cybrary-system-administrator.png" },
      { title: "CompTIA A+", src: "/img/certs/cybrary-comptia-a.png" },
    ],
  },
  {
    company: "TCM Security",
    logo: "/img/companies/tcmsecurity.jpg",
    certs: [
      { title: "Web Application Penetration Testing", src: "/img/certs/tcm-webapp-pentest.png" },
      { title: "API Hacking", src: "/img/certs/tcm-api-hacking.png" },
      { title: "Ethical Hacking", src: "/img/certs/tcm-ethical-hacking.png" },
      { title: "Movement, Pivoting, Persistence", src: "/img/certs/tcm-pivoting-persistence.png" },
      { title: "Privilege Escalation Windows", src: "/img/certs/tcm-privesc-windows.png" },
      { title: "Privilege Escalation Linux", src: "/img/certs/tcm-privesc-linux.png" },
      { title: "External Pentest Playbook", src: "/img/certs/tcm-external-pentest-playbook.png" },
      { title: "Governance, Risk and Compliance", src: "/img/certs/tcm-governance-risk-compliance.png" },
      { title: "OSINT", src: "/img/certs/tcm-osint.png" },
    ],
  },
  {
    company: "Try Hack Me",
    logo: "/img/companies/tryhackme.jpg",
    certs: [
      { title: "Offensive Pentest", src: "/img/certs/thm-offensive-pentesting.jpeg" },
      { title: "CompTIA Pentest+", src: "/img/certs/thm-comptia-pentest.jpeg" },
      { title: "JR Pentest", src: "/img/certs/thm-jr-pentester.jpeg" },
    ],
  },
  {
    company: "Other",
    certs: [
      { title: "Palo Alto Networks Cybersecurity Foundation", src: "/img/certs/paloalto-foundation.png" },
      { title: "EC Council Master OSINT", src: "/img/certs/eccouncil-master-osint.jpeg" },
      { title: "EC Council Reconnaissance", src: "/img/certs/eccouncil-master-recon.jpeg" },
      { title: "API Penetration Testing", src: "/img/certs/apisec-api-pentest.png" },
    ],
  },
];

const EDUCATION: EducationRow[] = [
  { 
    degree: "Cybersecurity", 
    institution: "Unicesumar", 
    location: "Brazil",
    logo: "/img/institutions/unicesumar.jpg",
    period: "2023 — 2025" 
  },
  { 
    degree: "Electrical Engineering", 
    institution: "Universidade Federal de Campina Grande", 
    location: "Brazil",
    logo: "/img/institutions/ufcg.jpg",
    period: "2014 — 2016" 
  },
];

const PROJECTS: ProjectItem[] = [
  {
    title: "0xh3x73rs Team",
    meta: "Founding Member (2023 — 2024)",
    bullets: [
      "Co-founded a bug bounty team, demonstrating leadership and initiative in the cybersecurity field.",
      "Collaborated with team members to identify and report vulnerabilities in various web applications.",
      "Contributed to the successful identification of significant security flaws.",
      "Developed expertise in vulnerability research and reporting methodologies.",
    ],
  },
];

const ACHIEVEMENTS: AchievementItem[] = [
  {
    name: "Cyberdefenders",
    href: "https://cyberdefenders.org/p/0xrh0d4m1n",
    badgeSrc: "https://cyberdefenders-storage.s3.me-central-1.amazonaws.com/profile-badges/0xrh0d4m1n.png",
  },
  {
    name: "TryHackMe",
    href: "https://tryhackme.com/p/0xrh0d4m1n",
    badgeSrc: "https://tryhackme-badges.s3.amazonaws.com/0xrh0d4m1n.png",
  },
  {
    name: "HackTheBox",
    href: "https://www.hackthebox.com/home/users/profile/1013077",
    badgeSrc: "https://www.hackthebox.com/badge/image/1013077",
  },
];

const LANGUAGES: LanguageItem[] = [
  { flag: "us", name: "English", level: "Fluent" },
  { flag: "br", name: "Portuguese", level: "Fluent" },
  { flag: "es", name: "Spanish", level: "Conversational" },
];

const RESUME_LINKS: ResumeLink[] = [
  { label: "English Resume", href: "/docs/resume-enus.pdf", flag: "us" },
  { label: "Portuguese Resume", href: "/docs/resume-ptbr.pdf", flag: "br" },
];

/* ────────────────────────────────────────────────────────────────── */
/*  Page component                                                   */
/* ────────────────────────────────────────────────────────────────── */

export default function AboutPage() {
  return (
    <div className="mx-auto w-[90vw] max-w-[900px] py-6">
      {/* ── Profile Header ──────────────────────────────────────── */}
      <Card className="relative overflow-hidden p-0">
        <div className="relative h-48 w-full sm:h-56">
          <Image
            src={PROFILE.banner}
            alt="Profile banner"
            fill
            priority
            className="object-cover object-top"
          />
        </div>

        <div className="relative px-6 pb-6 pt-0">
          <div className="absolute -top-16 left-6">
            <div className="h-32 w-32 overflow-hidden rounded-full border-4 border-background shadow-lg">
              <Image
                src={PROFILE.avatar}
                alt={PROFILE.name}
                width={128}
                height={128}
                priority
                className="h-full w-full object-cover"
              />
            </div>
          </div>

          <div className="h-20" />

          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold font-heading">
                  {PROFILE.name}
                </h1>
                <ShieldCheck className="h-5 w-5 text-primary" />
              </div>

              <p className="mt-1 text-sm text-muted-foreground">
                {PROFILE.headline}
              </p>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
                <span className="inline-flex items-center gap-1">
                  <MapPin className="h-3.5 w-3.5" />
                  {PROFILE.location}
                </span>
                <a
                  href={PROFILE.website}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-primary hover:underline"
                >
                  <Link2 className="h-3.5 w-3.5" />
                  Contact info
                </a>
              </div>

              <div className="mt-1 flex items-center gap-1 text-sm text-primary">
                <Users className="h-3.5 w-3.5" />
                {PROFILE.connections} connections
              </div>
            </div>

            <div className="flex shrink-0 items-center gap-2 rounded-md bg-muted/30 px-3 py-2">
              <img
                src={PROFILE.currentCompany.logo}
                alt={PROFILE.currentCompany.name}
                className="h-8 w-8 object-contain"
              />
              <span className="text-sm font-medium">
                {PROFILE.currentCompany.name}
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* ── About ───────────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">About</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {ABOUT_TEXT}
          </p>
        </CardContent>
      </Card>

      {/* ── Experience ──────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Experience</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {EXPERIENCE.map((exp, idx) => (
              <div key={`${exp.role}-${idx}`}>
                {idx > 0 && <Separator className="mb-6" />}
                <div className="flex gap-4">
                  <div className="shrink-0 pt-0.5">
                    {exp.logo ? (
                      <img
                        src={exp.logo}
                        alt=""
                        className="h-12 w-12 rounded-md border bg-background object-contain p-1"
                      />
                    ) : (
                      <div className="flex h-12 w-12 items-center justify-center rounded-md border bg-muted text-lg font-bold text-muted-foreground">
                        {exp.company.trim().slice(0, 1).toUpperCase()}
                      </div>
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-base font-semibold">{exp.role}</h3>
                    <div className="text-sm text-foreground/80">
                      {exp.company}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {exp.dates}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {exp.location}
                    </div>
                    {exp.bullets.length > 0 && (
                      <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                        {exp.bullets.map((b, bIdx) => (
                          <li key={bIdx}>{b}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Education ───────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Education</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {EDUCATION.map((row) => (
              <div key={row.degree} className="flex gap-3 rounded-lg border bg-card p-4">
                <div className="shrink-0 pt-0.5">
                  {row.logo ? (
                    <img
                      src={row.logo}
                      alt=""
                      className="h-12 w-12 rounded-md border bg-background object-contain p-1"
                    />
                  ) : (
                    <div className="flex h-12 w-12 items-center justify-center rounded-md border bg-muted text-lg font-bold text-muted-foreground">
                      🎓
                    </div>
                  )}
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold">{row.degree}</div>
                  <div className="text-xs text-foreground/80">{row.institution}</div>
                  <div className="text-xs text-muted-foreground">{row.period}</div>
                  {row.location && (
                    <div className="text-xs text-muted-foreground">{row.location}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Licenses & Certifications ───────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Licenses & Certifications</CardTitle>
        </CardHeader>
        <CardContent>
          <CertificationsSection groups={CERTIFICATIONS} />
        </CardContent>
      </Card>

      {/* ── Skills ──────────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Skills</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {SKILLS.map((cat, catIdx) => (
              <div key={cat.title}>
                {catIdx > 0 && <Separator className="mb-6" />}
                <h3 className="mb-3 text-sm font-semibold">{cat.title}</h3>
                <div className="flex flex-wrap gap-2">
                  {cat.badges.map((b) => (
                    <div
                      key={b.src}
                      className="rounded-full border bg-muted/20 px-3 py-1.5"
                      title={b.label}
                    >
                      <img
                        src={b.src}
                        alt={b.label}
                        className="h-6 object-contain"
                        loading="lazy"
                      />
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Achievements ──────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Achievements</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {ACHIEVEMENTS.map((a) => (
              <a
                key={a.name}
                href={a.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center overflow-hidden rounded-lg border bg-card p-2 transition-colors hover:border-primary/40 hover:bg-accent/30"
              >
                {a.badgeSrc ? (
                  <img
                    src={a.badgeSrc}
                    alt={`${a.name} badge`}
                    className="w-full object-contain"
                  />
                ) : (
                  <div className="flex h-full w-full items-center justify-center bg-muted/40 text-lg font-bold text-muted-foreground">
                    🏆 {a.name}
                  </div>
                )}
              </a>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Projects ────────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Projects</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {PROJECTS.map((p, idx) => (
              <div key={p.title}>
                {idx > 0 && <Separator className="mb-6" />}
                <div className="flex gap-4">
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-md border bg-muted text-lg font-bold text-muted-foreground">
                    📦
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-base font-semibold">{p.title}</div>
                    {p.meta && (
                      <div className="text-sm text-muted-foreground">
                        {p.meta}
                      </div>
                    )}
                    {p.bullets.length > 0 && (
                      <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                        {p.bullets.map((b, bIdx) => (
                          <li key={bIdx}>{b}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Languages ───────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Languages</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {LANGUAGES.map((l, idx) => (
              <div key={l.name}>
                {idx > 0 && <Separator className="mb-4" />}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <img
                      src={`https://flagcdn.com/24x18/${l.flag}.png`}
                      srcSet={`https://flagcdn.com/48x36/${l.flag}.png 2x`}
                      width="24"
                      height="18"
                      alt={`${l.name} flag`}
                      className="rounded-sm"
                    />
                    <span className="text-sm font-semibold">{l.name}</span>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {l.level}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Resume ──────────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">Resume</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {RESUME_LINKS.map((r) => (
              <a
                key={r.href}
                href={r.href}
                download
                className="group flex items-center gap-4 rounded-lg border border-primary/20 bg-primary/5 p-4 transition-all hover:border-primary/60 hover:bg-primary/10 hover:shadow-lg hover:shadow-primary/10"
              >
                <img
                  src={`https://flagcdn.com/48x36/${r.flag}.png`}
                  srcSet={`https://flagcdn.com/96x72/${r.flag}.png 2x`}
                  width="48"
                  height="36"
                  alt={`${r.label} flag`}
                  className="rounded-sm"
                />
                <div className="flex-1">
                  <div className="text-sm font-semibold">{r.label}</div>
                  <div className="text-xs text-muted-foreground">
                    Download PDF
                  </div>
                </div>
                <FontAwesomeIcon
                  icon={icons.download}
                  className="h-4 w-4 text-primary opacity-60 transition-opacity group-hover:opacity-100"
                />
              </a>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
