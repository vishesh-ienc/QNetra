export interface NavItem {
  to: string;
  label: string;
  /** The question this view answers — shown as a nav tooltip and on the page. */
  question: string;
  /** Requires completed scan results to be meaningful. */
  needsResults?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: 'Situation',
    items: [
      {
        to: '/',
        label: 'Command Center',
        question: 'What matters right now, and what should I do first?',
      },
      {
        to: '/scan',
        label: 'Scan',
        question: 'What did QNetra analyse, and how did the pipeline run?',
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
      },
      {
        to: '/findings',
        label: 'Findings',
        question: 'What raw evidence did the scanners record?',
        needsResults: true,
      },
      {
        to: '/cbom',
        label: 'CBOM',
        question: 'What is the standardised, exportable inventory?',
        needsResults: true,
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
      },
      {
        to: '/quantum',
        label: 'Quantum',
        question: 'What breaks under a quantum adversary, and how badly?',
        needsResults: true,
      },
      {
        to: '/mosca',
        label: 'Mosca',
        question: 'How urgent is migration for the data we protect?',
        needsResults: true,
      },
    ],
  },
  {
    label: 'Response',
    items: [
      {
        to: '/migration',
        label: 'PQC Migration',
        question: 'What do we migrate, in what order, and to what?',
        needsResults: true,
      },
      {
        to: '/reports',
        label: 'Reports',
        question: 'What can I hand to an auditor or a CISO?',
        needsResults: true,
      },
    ],
  },
];
