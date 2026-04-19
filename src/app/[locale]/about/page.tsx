import type { Metadata } from "next";
import Image from "next/image";
import { MapPin, Link2, Users, ShieldCheck } from "lucide-react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { getTranslations, setRequestLocale } from "next-intl/server";
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

interface Props {
  params: Promise<{ locale: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "about" });
  return { title: t("title") };
}

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
  avatar: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380552/Website/About/me_cgmy7s.jpg",
  banner: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380568/Website/About/b0740b2a8afc9453749b5e013a2db6fb_lp1jkn.png",
  currentCompany: {
    name: "Akamai Technologies",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380652/Website/Logos/akamai_qa6mgc.jpg",
  },
} as const;

const ABOUT_TEXT = "Cybersecurity professional with roots in Full Stack Web Development and Electrical Engineering. Started with electronics and microcontrollers, transitioned into Web Dev with the help of great mentors, moved to explore Blockchain Technologies, and then found a true calling in Cybersecurity where has been working in this field for years until these days. Completed many top-tier training, also practiced extensively in advanced scenarios of the cyber realm covering the full spectrum of Defense/Offensive techniques and strategies. Additionaly practices Bug Bounty in worldwide. Currently is specialized in Application, Microservices and API Protection with a deep understanding in DDoS mitigation and network-based threat defense (L3/4/7), working with WAFs, SIEM, SOAR, and IDS/IPS. Also deeply engaged in Cyber Threat Intelligence, Threat Modeling, Threat Hunting, Reverse Engineering, and Malware Analysis — to anticipate APT tactics and strengthen countermeasures. Driven by continuous learning and a healthy respect for how much there is still to learn.";

const EXPERIENCE: ExperienceItem[] = [
  {
    role: "Cyber Security Architect - SOC",
    company: "Akamai Technologies",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380652/Website/Logos/akamai_qa6mgc.jpg",
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
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380655/Website/Logos/nexusguard_anm0er.jpg",
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
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380656/Website/Logos/hackerone_tbhrhc.jpg",
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
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380654/Website/Logos/freelancer_ju378u.jpg",
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
    company: "Cisco",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386593/Website/Logos/cisco_plawrm.jpg",
    certs: [
      { title: "Security Operations Center (SOC)", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386370/Website/Certificates/Cisco/da9cb6db-e6ef-4bbd-adfa-008d90f98b33.png" },
      { title: "Network Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386392/Website/Certificates/Cisco/2e858664-bee1-4657-82aa-f2812b3be834.png" },
      { title: "Data Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386430/Website/Certificates/Cisco/8514c371-344c-4ad7-b265-3e1a7a40e2f5.png" },
      { title: "Endpoints and Systems", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386415/Website/Certificates/Cisco/763b16cd-4154-438c-8cb6-765aea7c8f80.png" },
    ],
  },
  {
    company: "Fortinet",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380653/Website/Logos/fortinet_o5oqzh.jpg",
    certs: [
      { title: "Fortinet Cybersecurity Associate", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382891/Website/Certificates/Fortinet/fortinet-fca_byssxe.png" },
      { title: "Fortinet Cybersecurity Fundamentals", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382893/Website/Certificates/Fortinet/fortinet-fcf_fk0ret.png" },
      { title: "Fortinet Network Security Level 3", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382896/Website/Certificates/Fortinet/fortinet-network-sec-level-3_cxixl4.png" },
      { title: "Fortinet Network Security Level 2", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382895/Website/Certificates/Fortinet/fortinet-network-sec-level-2_vhpx0s.png" },
      { title: "Fortinet Network Security Level 1", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382898/Website/Certificates/Fortinet/fortinet-network-sec-level-1_u7eojf.png" },
    ],
  },
  {
    company: "Palo Alto Networks",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385796/Website/Logos/paloaltonetworks_gfcnas.jpg",
    certs: [
      { title: "Palo Alto Networks Cyber Professional", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386839/Website/Certificates/PaloAltoNetworks/814210cf-d6b9-4007-aa09-0bc7a8b5ee23.png" },
      { title: "Security Operations", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386847/Website/Certificates/PaloAltoNetworks/72622c6b-c263-4963-b0f8-bf7f6eab0a0f.png" },
      { title: "Cloud Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386862/Website/Certificates/PaloAltoNetworks/e31716e4-74db-4f46-94df-ee17e25451ac.png" },
      { title: "Network Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386968/Website/Certificates/PaloAltoNetworks/8ba0f83e-443a-4082-b80d-e20178ff3b10.png" },
      { title: "Cyber Foundations", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776386976/Website/Certificates/PaloAltoNetworks/94850e4f-50da-41c1-8f71-8c9116c02658.png" },
    ],
  },
  {
    company: "IBM",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776388731/Website/Logos/ibm_wrggr5.jpg",
    certs: [
      { title: "Cyber Tools & Cyber Attacks", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389040/Website/Certificates/IBM/68ba10fe-9b46-494e-83d4-0fa32dab8df3.png" },
    ],
  },
  {
    company: "Google",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380654/Website/Logos/google_uyxjwn.jpg",
    certs: [
      { title: "Google Cyber Professional", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382932/Website/Certificates/Google/google-cyber-0_avf6f4.png" },
      { title: "Foundations of Cybersecurity", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382930/Website/Certificates/Google/google-cyber-1_vdiblh.png" },
      { title: "Manage Security Risks", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382920/Website/Certificates/Google/google-cyber-2_tey8dd.png" },
      { title: "Networks and Network Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382919/Website/Certificates/Google/google-cyber-3_e2ybpf.png" },
      { title: "Linux and SQL", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382925/Website/Certificates/Google/google-cyber-4_fk6a6v.png" },
      { title: "Assets Threats Vulnerabilities", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382922/Website/Certificates/Google/google-cyber-5_i83ctv.png" },
      { title: "Detection and Response", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382924/Website/Certificates/Google/google-cyber-6_bujdzr.png" },
      { title: "Cybersecurity Tasks with Python", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382929/Website/Certificates/Google/google-cyber-7_mmfvvg.png" },
      { title: "Preparation for Cybersecurity Jobs", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382927/Website/Certificates/Google/google-cyber-8_fcqmqb.png" },
    ],
  },
  {
    company: "Elastic",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385799/Website/Logos/elastic_qeukih.jpg",
    certs: [
      { title: "Threat Hunting with Network Telemetry", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776387585/Website/Certificates/Elastic/ca95d8ca-ec24-46fc-8eca-612c72b8f899.png" },
      { title: "Elastic Security for SIEM", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776387593/Website/Certificates/Elastic/9946f969-c6ae-42bd-b8d2-7152e645348b.png" },
      { title: "Data Analysis with Kibana", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776387610/Website/Certificates/Elastic/394588c9-4c81-4ffb-b6b6-0a843e9afe8f.png" }
    ],
  },
  {
    company: "EC-Council",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776387497/Website/Logos/eccouncil_cs75xq.jpg",
    certs: [
      { title: "Master Open Source Intelligence", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382875/Website/Certificates/ECCouncil/eccouncil-master-osint_lt4yce.jpg" },
      { title: "Reconnaissance for Cybersecurity", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382874/Website/Certificates/ECCouncil/eccouncil-master-recon_ray5zo.jpg" },
    ],
  },
  {
    company: "Cybrary",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380652/Website/Logos/cybrary_orpqyk.jpg",
    certs: [
      { title: "Offensive Penetration Testing", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382791/Website/Certificates/Cybrary/cybrary-offensive-pentest_oj61tx.png" },
      { title: "Advanced Penetration Testing", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382799/Website/Certificates/Cybrary/cybrary-advanced-pentest_tcabh7.png" },
      { title: "Penetration Testing", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382787/Website/Certificates/Cybrary/cybrary-become-pentester_okhqvo.png" },
      { title: "Penetration Testing & Ethical Hacking", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382797/Website/Certificates/Cybrary/cybrary-pentest-ethical-hacking_pwkfeq.png" },
      { title: "OWASP TOP 10", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382792/Website/Certificates/Cybrary/cybrary-owasp-top10_z7yzpw.png" },
      { title: "CompTIA Security+", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382793/Website/Certificates/Cybrary/cybrary-comptia-security_fmi1g6.png" },
      { title: "Cyber Kill Chain Framework", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382796/Website/Certificates/Cybrary/cybrary-cyber-kill-chain_fxxhl9.png" },
      { title: "MITRE ATT&CK Framework", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382787/Website/Certificates/Cybrary/cybrary-mitre-framework_lblvs6.png" },
      { title: "Security Operations Analyst (SOC)", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382786/Website/Certificates/Cybrary/cybrary-become-soc-1_dafhka.png" },
      { title: "CompTIA Linux+", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382800/Website/Certificates/Cybrary/cybrary-comptia-linux_xigmuw.png" },
      { title: "System Administrator", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382795/Website/Certificates/Cybrary/cybrary-system-administrator_psd4vr.png" },
      { title: "CompTIA A+", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382789/Website/Certificates/Cybrary/cybrary-comptia-a_hjro6t.png" },
    ],
  },
  {
    company: "TCM Security",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380655/Website/Logos/tcmsecurity_mtiztb.jpg",
    certs: [
      { title: "Web Application Penetration Testing", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383013/Website/Certificates/TCMSecurity/tcm-webapp-pentest_jnvlgs.png" },
      { title: "API Hacking", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383008/Website/Certificates/TCMSecurity/tcm-api-hacking_mehkef.png" },
      { title: "Ethical Hacking", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383004/Website/Certificates/TCMSecurity/tcm-ethical-hacking_kfycdv.png" },
      { title: "Movement, Pivoting, Persistence", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382999/Website/Certificates/TCMSecurity/tcm-pivoting-persistence_t8kaeg.png" },
      { title: "Privilege Escalation Windows", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383010/Website/Certificates/TCMSecurity/tcm-privesc-windows_jof6hq.png" },
      { title: "Privilege Escalation Linux", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383001/Website/Certificates/TCMSecurity/tcm-privesc-linux_wvflwz.png" },
      { title: "External Pentest Playbook", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383012/Website/Certificates/TCMSecurity/tcm-external-pentest-playbook_ezt8hu.png" },
      { title: "Governance, Risk and Compliance", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383002/Website/Certificates/TCMSecurity/tcm-governance-risk-compliance_uen4ae.png" },
      { title: "OSINT", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383007/Website/Certificates/TCMSecurity/tcm-osint_r9emgo.png" },
    ],
  },
  {
    company: "Try Hack Me",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380657/Website/Logos/tryhackme_iaq23u.jpg",
    certs: [
      { title: "Advanced Endpoint Investigations", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385232/Website/Certificates/TryHackMe/76bdd86d-50ac-471a-b033-de5c75200b2c.png" },
      { title: "DevSecOps", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385176/Website/Certificates/TryHackMe/f161cf8d-665c-482c-a3be-8567c192e987.png" },
      { title: "Security Engineer", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385138/Website/Certificates/TryHackMe/737cc321-0f38-4b23-9494-2f80aa121a83.png" },
      { title: "SOC Level 2", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385094/Website/Certificates/TryHackMe/db78e1b9-24f2-4d17-a325-7af67290e653.png" },
      { title: "SOC Level 1", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385033/Website/Certificates/TryHackMe/f7a09d38-18a5-458c-b452-a9a44125f3eb.png" },
      { title: "Offensive Pentest", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383029/Website/Certificates/TryHackMe/thm-offensive-pentesting_vpiiif.jpg" },
      { title: "CompTIA Pentest+", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383027/Website/Certificates/TryHackMe/thm-comptia-pentest_jzna2o.jpg" },
      { title: "Web Application Pentesting", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384729/Website/Certificates/TryHackMe/f6004adf-249f-4cac-a08d-0e4d3719bd10.png" },
      { title: "JR Pentest", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776383031/Website/Certificates/TryHackMe/thm-jr-pentester_gk6hbn.jpg" },
      { title: "Cyber Security 101", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384641/Website/Certificates/TryHackMe/b7b255e0-e9a8-4df2-8f0b-b6cab960cc43.png"},
      { title: "Intro to Cyber Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384230/Website/Certificates/TryHackMe/75da586a-3624-40a2-a413-32c94ccd7c16.png" },
      { title: "Web Fundamentals", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384284/Website/Certificates/TryHackMe/5575eb73-3989-4488-abc8-8fe0677704da.png" },
      { title: "Pre Security", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384172/Website/Certificates/TryHackMe/0cb8b976-f440-4c47-8c1a-11a1840f563d.png" },
      { title: "Complete Beginner", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776384494/Website/Certificates/TryHackMe/adc0b756-e594-4a67-8286-c5a6b2012ce7.png" },
    ],
  },
  {
    company: "APISec University",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385794/Website/Logos/apisecuniversity_zlhtah.jpg",
    certs: [
      { title: "OWASP API Security Top 10", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776388189/Website/Certificates/APISecUniversity/0278cf14-2c69-499b-af13-2aa756f22ec6.png" },
      { title: "API Penetration Testing", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776382855/Website/Certificates/APISecUniversity/apisec-api-pentest_cxszp4.png" },
    ],
  },
  {
    company: "LetsDefend",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385802/Website/Logos/letsdefend_n5kzxh.jpg",
    certs: [
      { title: "Malware Analysis", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385958/Website/Certificates/LetsDefend/b7143fc4-af93-49c5-bc30-f41daf05cd83.png" },
      { title: "Detection Engineering", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385906/Website/Certificates/LetsDefend/a4aaf86d-9893-468f-834e-9cd78e000dec.png" },
      { title: "Incident Responder", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385937/Website/Certificates/LetsDefend/749de596-f33f-4e8f-a8fb-c0ab63f073ae.png" },
      { title: "SOC Analyst", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385914/Website/Certificates/LetsDefend/07c281a9-3ee1-4a27-8f9e-d4f430450117.png" },
    ],
  },
  {
    company: "Cyberdefenders",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385805/Website/Logos/cyberdefenders_kld1nk.jpg",
    certs: [
      { title: "SOC Analyst Tier 1", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389333/Website/Certificates/CyberDefenders/63cc3138-6430-433b-b14a-08bd56b4780d.png" },
    ],
  },
  {
    company: "PentesterLab",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385808/Website/Logos/pentesterlab_zhj6od.jpg",
    certs: [
      { title: "Unix Badge", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389705/Website/Certificates/PentesterLab/d314086c-bebd-428f-9764-f4a0fc368c78.png" },
      { title: "Recon Badge", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389669/Website/Certificates/PentesterLab/91d38278-4597-4364-9972-1d4d5f5b5729.png" },
      { title: "HTTP Badge", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389691/Website/Certificates/PentesterLab/d45a6c6d-4c60-4c9b-bc0f-aec73d467e09.png" },
      { title: "PCAP Badge", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389679/Website/Certificates/PentesterLab/1f0a0fbe-a06d-4ecb-9cc8-7e0a23aed81a.png" },
      { title: "Essential Badge", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389657/Website/Certificates/PentesterLab/e49a953f-8c67-49c1-86e5-632435bc6871.png" },
    ],
  },
  {
    company: "Nexusguard",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380655/Website/Logos/nexusguard_anm0er.jpg",
    certs: [
      { title: "Nexusguard Certified Security Associate (NCSA)", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389498/Website/Certificates/Nexusguard/7739365e-80e8-4590-9da3-d8b7f444b4b3.png" },
    ],
  },
  {
    company: "Udemy",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776385814/Website/Logos/udemy_kh5fjc.jpg",
    certs: [
      { title: "Penetration Testing Bootcamp - Hackersploit Academy", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389974/Website/Certificates/Udemy/65f3cf37-9799-4095-9731-3a57d6103837.png" },
      { title: "Bounty Hunting & WebApp Hacking - NahamSec", src: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776389980/Website/Certificates/Udemy/2f698975-5295-486a-8e95-d014fbae4fcd.png" },
    ],
  },
];

const EDUCATION: EducationRow[] = [
  { 
    degree: "Cybersecurity", 
    institution: "Unicesumar", 
    location: "Brazil",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380663/Website/Logos/unicesumar_wvptkn.jpg",
    period: "Present"
  },
  { 
    degree: "Electrical Engineering", 
    institution: "Universidade Federal de Campina Grande", 
    location: "Brazil",
    logo: "https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380662/Website/Logos/ufcg_ro66lv.jpg",
    period: "2018"
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

export default async function AboutPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations({ locale, namespace: "about" });
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
                  {t("contactInfo")}
                </a>
              </div>

              <div className="mt-1 flex items-center gap-1 text-sm text-primary">
                <Users className="h-3.5 w-3.5" />
                {t("connections", { count: PROFILE.connections })}
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
          <CardTitle className="text-xl">{t("sectionAbout")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionExperience")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionEducation")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionCertifications")}</CardTitle>
        </CardHeader>
        <CardContent>
          <CertificationsSection groups={CERTIFICATIONS} />
        </CardContent>
      </Card>

      {/* ── Skills ──────────────────────────────────────────────── */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-xl">{t("sectionSkills")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionAchievements")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionProjects")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionLanguages")}</CardTitle>
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
          <CardTitle className="text-xl">{t("sectionResume")}</CardTitle>
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
                    {t("downloadPdf")}
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
