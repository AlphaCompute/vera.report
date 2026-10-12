/** Worked examples for the public summary of a confidential report. Each pair
 * describes the same situation: the "bad" version names people, places, dates
 * or contact details; the "good" one says what kind of wrongdoing it is and what
 * the reporter can show, without saying who they are. Unit tests check that the
 * good examples pass the on-device checks and every bad one is caught. */
export type SummaryExample = { topic: string; bad: string; good: string; why: string };

export const SUMMARY_EXAMPLES: readonly SummaryExample[] = [
  {
    topic: 'Healthcare billing',
    bad: 'I am Maria Lopez, billing supervisor at Northside Clinic in Dayton. On March 4, 2024 my manager Tom Reed told me to bill for visits that never happened.',
    good: 'A healthcare provider has billed a federal health program for patient visits that did not take place, over roughly a year. I have internal billing records.',
    why: 'Names a person, an employer, a city and an exact date, and gives away a role only one person holds.',
  },
  {
    topic: 'Investment fraud',
    bad: 'As the only compliance officer at Acme Capital LLC, I saw the CFO backdate client trades on 06/12/2023. Email me at m.lopez@example.com.',
    good: 'An investment firm appears to have backdated client trades to hide losses. I have emails and trade records from the period.',
    why: 'Names the company, a unique job, an exact date and a personal email address.',
  },
  {
    topic: 'Environmental harm',
    bad: 'Our plant at 1200 Riverside Drive dumps solvent into the river every Friday night. Call me on 419-555-0144.',
    good: 'A manufacturing site has repeatedly discharged chemical waste into a nearby river without a permit. I have photos and a log of when it happened.',
    why: 'Gives a street address and a phone number, which point straight to the reporter.',
  },
];
