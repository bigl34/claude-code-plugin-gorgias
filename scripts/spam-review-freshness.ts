import {
  listDayStates,
  listJournalSourceDates,
  liveLockAgeMs,
  pendingIntents,
  pendingRollbackIntents,
  readJournal,
  unresolvedAmbiguousOutcomes,
  unresolvedAmbiguousRollbackOutcomes,
} from "./spam-review-state.js";

export interface FreshnessSnapshot {
  latestCompletedDate: string | null;
  latestCompletedAt: string | null;
  pendingNotifications: number;
  failedDates: string[];
  unresolvedJournalDates: string[];
  liveLockAgeMs: number | null;
  stateReadError: boolean;
}

export interface FreshnessResult {
  healthy: boolean;
  expectedSourceDate: string | null;
  latestCompletedDate: string | null;
  latestCompletedAt: string | null;
  pendingNotifications: number;
  failedDates: string[];
  unresolvedJournalDates: string[];
  staleLiveLock: boolean;
  stateReadError: boolean;
  problem?: string;
}

export function collectFreshnessSnapshot(
  stateRoot: string,
  now = new Date(),
): FreshnessSnapshot {
  let stateReadError = false;
  let states: ReturnType<typeof listDayStates> = [];
  try {
    states = listDayStates(stateRoot);
  } catch {
    stateReadError = true;
  }
  const completed = states.filter(
    (state) => state.status === "complete" || state.status === "complete_capped",
  );
  const latest = completed.at(-1) ?? null;
  const pendingNotifications = states.filter((state) => state.notificationPending).length;
  const failedDates = states
    .filter((state) => state.status === "failed")
    .map((state) => state.sourceDate);
  let journalDates: string[] = [];
  try {
    journalDates = listJournalSourceDates(stateRoot);
  } catch {
    stateReadError = true;
  }
  const unresolvedJournalDates = journalDates.flatMap((sourceDate) => {
    try {
      const events = readJournal(stateRoot, sourceDate);
      const unresolved = pendingIntents(events).length
        + unresolvedAmbiguousOutcomes(events).length
        + pendingRollbackIntents(events).length
        + unresolvedAmbiguousRollbackOutcomes(events).length;
      return unresolved > 0 ? [sourceDate] : [];
    } catch {
      return [sourceDate];
    }
  });
  return {
    latestCompletedDate: latest?.sourceDate ?? null,
    latestCompletedAt: latest?.completedAt ?? null,
    pendingNotifications,
    failedDates,
    unresolvedJournalDates,
    liveLockAgeMs: liveLockAgeMs(stateRoot, now),
    stateReadError,
  };
}

export function evaluateFreshness(
  snapshot: FreshnessSnapshot,
  now = new Date(),
  maxAgeHours = 36,
  expectedSourceDate?: string,
): FreshnessResult {
  const completedAtMs = snapshot.latestCompletedAt
    ? Date.parse(snapshot.latestCompletedAt)
    : Number.NaN;
  const staleLiveLock = snapshot.liveLockAgeMs !== null
    && snapshot.liveLockAgeMs > 45 * 60_000;
  const stale = !Number.isFinite(completedAtMs)
    || now.getTime() - completedAtMs > maxAgeHours * 3_600_000;
  const problems: string[] = [];
  if (snapshot.stateReadError) {
    problems.push("state directory is unreadable or contains corrupt JSON");
  }
  if (stale) problems.push(`no completed source date within ${maxAgeHours}h`);
  if (
    expectedSourceDate
    && (!snapshot.latestCompletedDate || snapshot.latestCompletedDate < expectedSourceDate)
  ) {
    problems.push(`latest completed source date is behind expected ${expectedSourceDate}`);
  }
  if (Number.isFinite(completedAtMs) && completedAtMs - now.getTime() > 10 * 60_000) {
    problems.push("latest completion timestamp is more than 10 minutes in the future");
  }
  if (snapshot.failedDates.length > 0) {
    problems.push(`failed source dates: ${snapshot.failedDates.slice(0, 5).join(", ")}`);
  }
  if (snapshot.pendingNotifications > 0) {
    problems.push(`${snapshot.pendingNotifications} pending Slack notification(s)`);
  }
  if (snapshot.unresolvedJournalDates.length > 0) {
    problems.push(
      `unresolved mutation journal: ${snapshot.unresolvedJournalDates.slice(0, 5).join(", ")}`,
    );
  }
  if (staleLiveLock) problems.push("live writer lock is older than 45 minutes");
  return {
    healthy: problems.length === 0,
    expectedSourceDate: expectedSourceDate ?? null,
    latestCompletedDate: snapshot.latestCompletedDate,
    latestCompletedAt: snapshot.latestCompletedAt,
    pendingNotifications: snapshot.pendingNotifications,
    failedDates: snapshot.failedDates,
    unresolvedJournalDates: snapshot.unresolvedJournalDates,
    staleLiveLock,
    stateReadError: snapshot.stateReadError,
    ...(problems.length ? { problem: problems.join("; ") } : {}),
  };
}

export function assessFreshness(
  stateRoot: string,
  now = new Date(),
  maxAgeHours = 36,
  expectedSourceDate?: string,
): FreshnessResult {
  return evaluateFreshness(collectFreshnessSnapshot(stateRoot, now), now, maxAgeHours, expectedSourceDate);
}
