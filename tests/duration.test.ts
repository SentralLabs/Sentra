import { describe, it, expect } from "vitest";
import { parseDuration, durationToDate } from "../src/utils/duration.js";

describe("Duration", () => {

    it("should parse short units", () => {
        expect(parseDuration("30s")).toBe(30_000);
        expect(parseDuration("15m")).toBe(15 * 60_000);
        expect(parseDuration("2h")).toBe(2 * 3_600_000);
        expect(parseDuration("7d")).toBe(7 * 86_400_000);
        expect(parseDuration("1w")).toBe(7 * 86_400_000);
    });

    it("should parse long units with optional whitespace", () => {
        expect(parseDuration("2 hours")).toBe(2 * 3_600_000);
        expect(parseDuration("1 day")).toBe(86_400_000);
        expect(parseDuration("90 seconds")).toBe(90_000);
        expect(parseDuration(" 10 mins ")).toBe(10 * 60_000);
    });

    it("should be case-insensitive", () => {
        expect(parseDuration("15M")).toBe(15 * 60_000);
        expect(parseDuration("1 Day")).toBe(86_400_000);
    });

    it("should accept zero", () => {
        expect(parseDuration("0s")).toBe(0);
    });

    it("should reject malformed input", () => {
        expect(() => parseDuration("")).toThrow();
        expect(() => parseDuration("15")).toThrow();
        expect(() => parseDuration("m")).toThrow();
        expect(() => parseDuration("-5m")).toThrow();
        expect(() => parseDuration("1.5h")).toThrow();
        expect(() => parseDuration("5 fortnights")).toThrow();
        expect(() => parseDuration(undefined as unknown as string)).toThrow();
    });

    it("should produce a date offset from now", () => {
        const from = 1_000_000;
        expect(durationToDate("1m", from).getTime()).toBe(from + 60_000);
    });

});
