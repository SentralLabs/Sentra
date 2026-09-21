const UNIT_MS: Record<string, number> = {
    s: 1000, sec: 1000, secs: 1000, second: 1000, seconds: 1000,
    m: 60_000, min: 60_000, mins: 60_000, minute: 60_000, minutes: 60_000,
    h: 3_600_000, hr: 3_600_000, hrs: 3_600_000, hour: 3_600_000, hours: 3_600_000,
    d: 86_400_000, day: 86_400_000, days: 86_400_000,
    w: 604_800_000, week: 604_800_000, weeks: 604_800_000
};

/**
 * Parses a human-readable duration such as "15m", "2 hours" or "30d"
 * into milliseconds. Throws on anything it cannot understand so that
 * bad configuration fails at startup rather than at first use.
 */
export function parseDuration(duration: string): number {
    if (typeof duration !== "string") {
        throw new Error(`Invalid duration: ${String(duration)}`);
    }

    const match = duration.trim().match(/^(\d+)\s*([a-z]+)$/i);

    if (!match) {
        throw new Error(`Invalid duration: "${duration}"`);
    }

    const value = Number(match[1]);
    const unit = UNIT_MS[match[2]!.toLowerCase()];

    if (unit === undefined) {
        throw new Error(`Invalid duration unit in "${duration}"`);
    }

    return value * unit;
}

export function durationToDate(duration: string, from: number = Date.now()): Date {
    return new Date(from + parseDuration(duration));
}
