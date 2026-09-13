import type { PipelineStage } from '../../api/types';

export interface NavItem {
  to: string;
  label: string;
  /** The question this view answers — shown as a nav tooltip and on the page. */
  question: string;
  /** Requires completed scan results to be meaningful. */
  needsResults?: boolean;
  /** This item is the primary result destination — render with extra emphasis. */
  isPrimary?: boolean;
  /**
   * The pipeline stage that must complete before this page is meaningful.
   * Used by SideNav to show processing/pending indicators during an active scan.
   */
  requiredStage?: PipelineStage;
  /**
   * True for the Scan History item — styled differently from result-dependent items.
   * Always accessible regardless of scan state.
   */
  isHistory?: boolean;
}

export interface NavGroup {
  label: string;
  /** If true, the group label is visually suppressed — used for the top primary item. */
  unlabeled?: boolean;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: 'Overview',
    unlabeled: true,
    items: [
      {
        to: '/',
        label: 'Cryptographic Posture',
        question: 'What is the cryptographic security posture of this target?',
        needsResults: true,
        isPrimary: true,
        requiredStage: 'RISK_ANALYSIS',
      },
    ],
  },
  {
    label: 'Scan',
    items: [
      {
        to: '/scan',
        label: 'New Scan',
        question: 'Upload an artifact and start a cryptographic discovery scan.',
      },
    ],
  },
  {
    label: 'History',
    items: [
      {
        to: '/history',
        label: 'Scan History',
        question: 'Browse previous scans and restore any analysis without re-uploading.',
        isHistory: true,
      },
    ],
  },
  {
    label: 'Inventory',
    items: [
      {
        to: '/assets',
        label: 'Crypto Assets',
        question: 'What cryptography actually exists in this target?',
        needsResults: true,
        requiredStage: 'NORMALIZATION',
      },
      {
        to: '/findings',
        label: 'Evidence',
        question: 'What raw evidence did the scanners record?',
        needsResults: true,
        requiredStage: 'DISCOVERY',
      },
      {
        to: '/cbom',
        label: 'CBOM',
        question: 'What is the standardised, exportable inventory?',
        needsResults: true,
        requiredStage: 'CBOM',
      },
    ],
  },
  {
    label: 'Exposure',
    items: [
      {
        to: '/risk',
        label: 'Risk',
        question: 'Which assets carry the most risk, and why?',
        needsResults: true,
        requiredStage: 'RISK_ANALYSIS',
      },
      {
        to: '/quantum',
        label: 'Quantum Exposure',
        question: 'What breaks under a quantum adversary, and how badly?',
        needsResults: true,
        requiredStage: 'CLASSIFICATION',
      },
      {
        to: '/mosca',
        label: 'Mosca / HNDL',
        question: 'How urgent is migration for the data we protect?',
        needsResults: true,
        requiredStage: 'MOSCA_ANALYSIS',
      },
    ],
  },
  {
    label: 'Response',
    items: [
      {
        to: '/migration',
        label: 'PQC Migration Plan',
        question: 'What do we migrate, in what order, and to what?',
        needsResults: true,
        requiredStage: 'PQC_ANALYSIS',
      },
      {
        to: '/reports',
        label: 'Reports & Exports',
        question: 'What can I hand to an auditor or a CISO?',
        needsResults: true,
        requiredStage: 'COMPLETED',
      },
    ],
  },
];
