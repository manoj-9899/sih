import { ActiveTab } from './navigation';

export interface TourStep {
  id: number;
  chapter: string;
  tabKey: ActiveTab;
  title: string;
  storyAnalogy: string;
  targetObjective: string;
  highlightSelector?: string;
  whyThisMatters: string;
  whatHappensNext: string;
  behindTheScenesExplanation: string;
  actionButtonLabel?: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    id: 1,
    chapter: 'Step 1 of 5 • Detective Story',
    tabKey: 'documents',
    title: 'Lock the Secret Document',
    storyAnalogy:
      'Imagine placing a confidential file into a super-secure safe box. Instead of giving everyone the same key combination, the safe creates a separate digital key for each person you choose.',
    targetObjective:
      '1. Click the first document on the left.\n2. Make sure Alice and Bob are checked (leave Charlie unchecked).\n3. Click the glowing button: "GENERATE ENCRYPTED PACKAGE".',
    highlightSelector: '[data-tour-target="generate-package-btn"]',
    whyThisMatters:
      'Because Charlie was not checked, he has no key. If he steals the file, he sees only scrambled nonsense that even future supercomputers cannot crack.',
    whatHappensNext:
      'The document is locked! Alice and Bob now have their own keys. Next, we will watch Alice unlock her copy.',
    behindTheScenesExplanation:
      'The document was encrypted using AES-256-GCM. The main secret key was wrapped individually for Alice and Bob using NIST ML-KEM-768 quantum-safe lattice mathematics.',
    actionButtonLabel: 'Go to Documents',
  },
  {
    id: 2,
    chapter: 'Step 2 of 5 • Detective Story',
    tabKey: 'decrypt',
    title: 'Alice Opens Her Copy (Invisible Watermark)',
    storyAnalogy:
      'When Alice uses her key to unlock the file, her screen secretly adds an invisible watermark between the words before displaying it. To Alice, the text looks 100% normal.',
    targetObjective:
      '1. Check that Dr. Alice Vance is signed in.\n2. Click the glowing button: "Decrypt document".\n3. Click "Inspect watermark" to see her hidden code.',
    highlightSelector: '[data-tour-target="decrypt-recipient-btn"]',
    whyThisMatters:
      'Even if Alice copies the text or takes a screenshot, her secret invisible stamp is embedded inside the words. We will always know this copy was hers.',
    whatHappensNext:
      'Alice has opened her copy safely. Now let’s switch to Bob, who will also open his copy—and decide to leak it online!',
    behindTheScenesExplanation:
      'Alice’s hardware key unlocked the session key. Before displaying the text, zero-width spaces (invisible Unicode) were embedded with a 128-bit session ID and CRC-16 error check.',
    actionButtonLabel: 'Go to Decrypt',
  },
  {
    id: 3,
    chapter: 'Step 3 of 5 • Detective Story',
    tabKey: 'decrypt',
    title: 'Bob Leaks His Copy Online',
    storyAnalogy:
      'Now Bob opens the same document using his own key. His screen stamps his unique watermark. Believing nobody can trace it back to him, Bob leaks his copy to the public!',
    targetObjective:
      '1. Switch identity to Col. Bob Martinez.\n2. Click "Decrypt document".\n3. Click the red button: "Simulate anonymous leak of Col. Bob Martinez\'s copy".',
    highlightSelector: '[data-tour-target="simulate-leak-btn"]',
    whyThisMatters:
      'Alice and Bob read the exact same words on their screens. But Bob has no idea that his identity is invisibly hidden between the words of his copy.',
    whatHappensNext:
      'The leaked text has been copied to our Forensic Lab! Let’s scan it to find out who leaked it.',
    behindTheScenesExplanation:
      'Bob signed an immutable receipt using NIST ML-DSA-65 signatures, which was ratified by 4 air-gapped validator nodes and committed to the ledger.',
    actionButtonLabel: 'Select Bob & Simulate Leak',
  },
  {
    id: 4,
    chapter: 'Step 4 of 5 • Detective Story',
    tabKey: 'forensics',
    title: 'Scan the Leak & Catch the Culprit',
    storyAnalogy:
      'Security officers found an anonymous leaked document on the internet. We run this text through our digital scanner to see whose invisible watermark is hidden inside.',
    targetObjective:
      'Click the glowing button: "Analyze document" to scan the leaked text.',
    highlightSelector: '[data-tour-target="execute-attribution-btn"]',
    whyThisMatters:
      'The scanner immediately recovers Bob’s hidden watermark and checks our tamper-proof records. We now have 100% indisputable proof that Bob leaked the file.',
    whatHappensNext:
      'Bob is caught! But what if Bob tries to get an IT friend to delete his name from the system logs? Let’s test that in Step 5.',
    behindTheScenesExplanation:
      'The blind extractor recovered the 16-bit sync word (0xA55A), verified the CRC-16 checksum, and matched the session watermark commitment to Bob’s transaction on the ledger.',
    actionButtonLabel: 'Go to Forensics',
  },
  {
    id: 5,
    chapter: 'Step 5 of 5 • Detective Story',
    tabKey: 'ledger',
    title: 'Can Anyone Erase the Records?',
    storyAnalogy:
      'What if Bob has a friend in the IT department who tries to edit the database logs to erase Bob’s name? Watch what happens when an attacker tries to tamper with history.',
    targetObjective:
      '1. Click the red button: "Simulate rogue admin tamper".\n2. Click "Audit entire chain" to watch the tamper alarm trigger.\n3. Click "Restore quorum integrity" to fix it.',
    highlightSelector: '[data-tour-target="tamper-demo-btn"]',
    whyThisMatters:
      'Because the audit record is synchronized across 4 independent computers, changing even a single letter breaks the mathematical chain and gets rejected immediately.',
    whatHappensNext:
      'Integrity restored! You have completed the tour and learned how secret documents are protected, watermarked, and traced.',
    behindTheScenesExplanation:
      'Modifying transaction data alters the Merkle root and the previous block hash chain (SHA-256), causing validator quorum consensus to reject the altered state.',
    actionButtonLabel: 'Go to Ledger',
  },
];
