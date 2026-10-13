import { describe, expect, it } from "vitest";
import { wrapWords } from "../../src/lib/shapes";

const chars = (s: string) => s.length; // one unit per character

describe("wrapWords", () => {
  it("breaks between words, as TMT wraps a name", () => {
    expect(wrapWords("Account-Information Service", 20, chars)).toBe("Account-Information\nService");
    expect(wrapWords("Inter-Bank Payment Network", 18, chars)).toBe("Inter-Bank Payment\nNetwork");
  });
  it("keeps a word wider than the line whole", () => {
    expect(wrapWords("Authentication Service", 10, chars)).toBe("Authentication\nService");
  });
  it("keeps short names and the user's own line breaks", () => {
    expect(wrapWords("Student", 20, chars)).toBe("Student");
    expect(wrapWords("Bank\nStaff", 20, chars)).toBe("Bank\nStaff");
  });
});
