package com.zeroproof.service;

import java.time.Year;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Heuristic extraction of name, date of birth and document type from raw document text.
 * Ported from the legacy Node analyzer. The legacy hardcoded "identity registry" that overwrote
 * extracted values for specific people was intentionally NOT ported.
 */
public final class DocumentAnalyzer {
    private DocumentAnalyzer() { }

    public record Result(String name, String dateOfBirth, String documentType, String status, String reason) { }

    private static final List<String> NOISE_WORDS = Arrays.asList(
            "government", "governmant", "govermant", "goverment", "govenment",
            "india", "lndia", "indla", "indian", "aadhaar", "aadhar", "aadheer",
            "authority", "identification", "enrollment", "enrolment",
            "unique", "vid", "address", "male", "female", "gender",
            "dob", "birth", "date", "year", "signature", "help", "download",
            "maadhaar", "uidai", "www", "http", "phone", "mobile", "email",
            "student", "card", "valid", "until",
            "board", "university", "college", "school", "department",
            "institute", "technology", "polytechnic", "academy", "centre", "center",
            "father", "mother", "son", "daughter", "wife", "husband",
            "grade", "semester", "marks", "total", "subject", "result",
            "certificate", "examination", "register", "number", "roll", "class",
            "print", "issued", "expiry", "photo",
            "village", "town", "city", "state", "district", "post", "office",
            "road", "street", "nagar", "colony", "sector", "layout", "stage",
            "bharat", "sarkar", "pradesh", "karnataka", "maharashtra", "tamil",
            "bihar", "delhi", "pune", "mumbai", "bangalore", "bengaluru", "chennai",
            "floor", "house", "flat", "block", "near", "opposite", "behind",
            "weight", "blood", "group", "height", "contact",
            "republic", "verify", "verification", "scan",
            "door", "ward", "care", "self", "relation", "spouse",
            "residency", "theatre", "cross", "main",
            "education", "secondary", "pre-university", "composite",
            "english", "hindi", "sanskrit", "science", "physics", "chemistry",
            "mathematics", "computer", "language",
            "hundred", "thousand", "only", "ninety", "eighty", "seventy",
            "sixty", "fifty", "forty", "thirty", "twenty",
            "passed", "candidate", "mentioned", "below", "following", "details",
            "certify", "secretary", "chairman", "director",
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
            "ref", "code", "south", "north", "east", "west");

    private static final List<String> SHORT_WORDS = Arrays.asList(
            "the", "and", "for", "was", "are", "but", "not", "you", "all",
            "can", "had", "her", "one", "our", "out", "its", "his", "how",
            "old", "new", "now", "way", "who", "did", "get", "has", "too",
            "him", "let", "say", "she", "use", "any", "few", "got", "own",
            "set", "try", "ask", "put", "run", "big", "end", "far", "yet",
            "this", "that", "with", "from", "have", "been", "were", "will",
            "would", "could", "over", "into", "just", "than", "them", "then",
            "each", "make", "like", "long", "look", "many", "some", "what",
            "when", "which", "their", "about", "these", "other", "first");

    private static final List<String> NAME_STOP = Arrays.asList(
            "register", "reg", "roll", "number", "no", "male", "female", "dob", "date", "birth");

    private static final Pattern NOISE_TAIL = Pattern.compile(
            "\\b(Register|Reg|Roll|Enroll|Number|No|Male|Female|DOB|Date|Birth|Year|Address|Son|Daughter|Father|Mother|S/O|D/O|C/O|W/O)\\b.*",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern NAME_LABEL = Pattern.compile(
            "(?:Candidate'?s?\\s*|Student\\s*)?(?:Name|naam)\\s*[:;\\-=]?\\s*(.*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BAD_PREFIX = Pattern.compile(
            "(?:Father|Mother|Husband|Wife|Spouse|Parent|Course|Subject|College|School|University|Institution|Department|Branch|Bank|Company|State|City|District|Village|Registrar|Witness|Author)'?s?\\s*$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PARENT_NAME = Pattern.compile(
            "(?:Father|Mother|Husband|Wife|Spouse|Parent)'?s?\\s*Name", Pattern.CASE_INSENSITIVE);
    private static final String DOB_LABEL = "(?:D\\.?O\\.?B\\.?|Date\\s*of\\s*Birth|Birth\\s*Date)";
    private static final Pattern DOB_SAME_LINE = Pattern.compile(
            DOB_LABEL + "\\s*[:;\\-=]?\\s*(\\d{1,2}\\s*[/.\\-]\\s*\\d{1,2}\\s*[/.\\-]\\s*\\d{2,4})", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOB_LABEL_ALONE = Pattern.compile(DOB_LABEL + "\\s*[:;\\-=]?\\s*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOB_YEAR = Pattern.compile(
            "(?:D\\.?O\\.?B\\.?|Date\\s*of\\s*Birth|Year\\s*of\\s*Birth|Y\\.?O\\.?B\\.?|Birth)\\s*[:;\\-=]?\\s*(\\d{4})",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern FATHER_LINE = Pattern.compile(
            "(?:Father'?s?\\s*Name|S/O|D/O|C/O|W/O)\\s*[:;\\-\\u00a9]?\\s*(.*)", Pattern.CASE_INSENSITIVE);

    public static Result analyze(String text) {
        if (text == null || text.trim().length() < 5) {
            return new Result("", "", "other", "UNREADABLE",
                    "No readable text found. The document image may be blurry, inverted, or not an identity document.");
        }
        String type = detectType(text);
        String name = correctSurname(extractName(text, type), text);
        String dob = extractDob(text, type);

        String mapped = switch (type) {
            case "aadhaar" -> "id_card";
            case "marks_card", "grade_card" -> "grade_card";
            default -> "other";
        };
        boolean ok = !name.isEmpty() && !dob.isEmpty();
        return new Result(name, dob, mapped, ok ? "SUCCESS" : "NO_DATA_FOUND",
                ok ? null : "Could not extract Name or Date of Birth. The document image might be blurry, inverted, cropped, "
                        + "or has low-contrast text. Please verify and fill in details manually.");
    }

    // ---------------- name ----------------

    static String cleanNameLine(String line) {
        String rest = NOISE_TAIL.matcher(line).replaceAll("");
        String cleaned = rest.replaceAll("[^A-Za-z\\s]", " ");
        StringBuilder sb = new StringBuilder();
        for (String w : cleaned.split("\\s+")) {
            if (w.isEmpty()) continue;
            if (w.equals(w.toLowerCase()) && w.length() > 1) break;
            if (NAME_STOP.contains(w.toLowerCase())) break;
            if (sb.length() > 0) sb.append(' ');
            sb.append(w);
        }
        return sb.toString().trim();
    }

    static boolean looksLikeName(String cleaned) {
        if (cleaned.length() < 4) return false;
        String[] words = cleaned.split("\\s+");
        if (words.length < 2 || words.length > 5) return false;
        boolean real = false;
        for (String w : words) {
            if (w.length() >= 3) real = true;
            if (!w.matches("[A-Za-z]+")) return false;
        }
        return real;
    }

    static boolean isNoisyLine(String text) {
        String lower = text.toLowerCase();
        String[] words = lower.split("\\s+");
        if (words.length < 2) return true;
        for (String nw : NOISE_WORDS) {
            if (lower.contains(nw)) return true;
        }
        for (String w : words) {
            if (SHORT_WORDS.contains(w)) return true;
        }
        long digits = text.chars().filter(Character::isDigit).count();
        if (digits > 2) return true;
        return lower.length() < 4;
    }

    private static boolean acceptable(String cleaned, int minLen) {
        return cleaned.length() >= minLen && looksLikeName(cleaned) && !isNoisyLine(cleaned);
    }

    static String[] lines(String text) {
        return Arrays.stream(text.split("[\\n\\r]+")).map(String::trim).filter(l -> !l.isEmpty()).toArray(String[]::new);
    }

    static String extractName(String text, String type) {
        String[] lines = lines(text);
        for (int i = 0; i < lines.length; i++) {
            Matcher m = NAME_LABEL.matcher(lines[i]);
            if (!m.find()) continue;
            String prefix = lines[i].substring(0, m.start()).trim();
            if (BAD_PREFIX.matcher(prefix).find()) continue;

            String val = cleanNameLine(m.group(1));
            if (acceptable(val, 3)) return val;

            for (int j = i + 1; j < Math.min(i + 4, lines.length); j++) {
                if (PARENT_NAME.matcher(lines[j]).find()) break;
                String next = cleanNameLine(lines[j]);
                if (acceptable(next, 3)) return next;
            }
        }
        if (type.equals("aadhaar")) {
            for (int i = 0; i < lines.length; i++) {
                String lower = lines[i].toLowerCase();
                if (lower.contains("dob") || Pattern.compile("\\b(male|female)\\b").matcher(lower).find()) {
                    for (int j = i - 1; j >= Math.max(0, i - 4); j--) {
                        String c = cleanNameLine(lines[j]);
                        if (acceptable(c, 3)) return c;
                    }
                }
            }
            for (String line : lines) {
                String c = cleanNameLine(line);
                if (c.length() < 5 || isNoisyLine(c)) continue;
                String[] words = c.split("\\s+");
                if (words.length < 2 || words.length > 4) continue;
                boolean pattern = Arrays.stream(words).allMatch(w -> w.matches("[A-Z][A-Za-z]*"));
                if (pattern) return c;
            }
        }
        if (type.equals("marks_card") || type.equals("grade_card")) {
            for (String line : lines) {
                String c = cleanNameLine(line);
                if (acceptable(c, 5)) return c;
            }
        }
        return "";
    }

    // ---------------- date of birth ----------------

    static String ocrFix(String t) {
        return t.replaceAll("(\\d)O", "$1" + "0").replaceAll("O(\\d)", "0" + "$1")
                .replaceAll("(\\d)l", "$1" + "1").replaceAll("l(\\d)", "1" + "$1")
                .replaceAll("(\\d)I", "$1" + "1").replaceAll("I(\\d)", "1" + "$1");
    }

    static String extractDob(String original, String type) {
        String fixed = ocrFix(original);
        for (String src : new String[]{original, fixed}) {
            Matcher m = DOB_SAME_LINE.matcher(src);
            if (m.find()) {
                String p = parseDate(m.group(1));
                if (p != null) return p;
            }
        }
        String[] lines = lines(original);
        for (int i = 0; i < lines.length; i++) {
            if (!DOB_LABEL_ALONE.matcher(lines[i]).find()) continue;
            for (int j = i + 1; j < Math.min(i + 3, lines.length); j++) {
                String next = lines[j].trim().replace("O", "0").replace("l", "1").replace("I", "1");
                Matcher iso = Pattern.compile("(\\d{4})\\s*-\\s*(\\d{2})\\s*-\\s*(\\d{2})").matcher(next);
                if (iso.find()) {
                    String p = parseDate(iso.group(1) + "-" + iso.group(2) + "-" + iso.group(3));
                    if (p != null) return p;
                }
                Matcher d = Pattern.compile("(\\d{1,4})\\s*[/.\\-]\\s*(\\d{1,2})\\s*[/.\\-]\\s*(\\d{1,4})").matcher(next);
                if (d.find()) {
                    String p = parseDate(d.group(1) + "-" + d.group(2) + "-" + d.group(3));
                    if (p != null) return p;
                }
            }
        }
        int maxYear = Year.now().getValue();
        for (String src : new String[]{original, fixed}) {
            Matcher m = DOB_YEAR.matcher(src);
            if (m.find()) {
                int y = Integer.parseInt(m.group(1));
                if (y >= 1920 && y <= maxYear) return y + "-01-01";
            }
        }
        if (!type.equals("other")) {
            Matcher m = Pattern.compile("\\d{1,2}\\s*[/.\\-]\\s*\\d{1,2}\\s*[/.\\-]\\s*\\d{2,4}").matcher(fixed);
            while (m.find()) {
                String p = parseDate(m.group());
                if (p != null) return p;
            }
            Matcher y = Pattern.compile("\\b(19[3-9]\\d|200\\d|201\\d|202[0-5])\\b").matcher(fixed);
            if (y.find()) return y.group(1) + "-01-01";
        }
        return "";
    }

    static String parseDate(String raw) {
        String d = raw.trim().replaceAll("\\s+", "").replaceAll("[/.\\-]", "-");
        String[] parts = d.split("-");
        if (parts.length != 3) return null;
        int yyyy, mm, dd;
        try {
            if (parts[0].length() == 4) {
                yyyy = Integer.parseInt(parts[0]);
                mm = Integer.parseInt(parts[1]);
                dd = Integer.parseInt(parts[2]);
            } else if (parts[2].length() == 4) {
                dd = Integer.parseInt(parts[0]);
                mm = Integer.parseInt(parts[1]);
                yyyy = Integer.parseInt(parts[2]);
            } else if (parts[2].length() == 2) {
                dd = Integer.parseInt(parts[0]);
                mm = Integer.parseInt(parts[1]);
                int yy = Integer.parseInt(parts[2]);
                yyyy = yy > 50 ? 1900 + yy : 2000 + yy;
            } else {
                return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        if (yyyy < 1920 || yyyy > Year.now().getValue() || mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
        return String.format("%04d-%02d-%02d", yyyy, mm, dd);
    }

    // ---------------- type / correction ----------------

    static String detectType(String text) {
        String t = text.toLowerCase();
        if (t.contains("aadhaar") || t.contains("aadhar") || t.contains("uidai") || t.contains("unique identification")
                || Pattern.compile("gov\\w*ment\\w*\\s*of\\s*\\w*ndia").matcher(t).find()
                || Pattern.compile("govenment\\s*of").matcher(t).find()) {
            return "aadhaar";
        }
        if (t.contains("university") || t.contains("board") || t.contains("marks") || t.contains("examination")
                || t.contains("pre-university") || t.contains("kseeb")) {
            return "marks_card";
        }
        if (t.contains("grade") || t.contains("semester") || t.contains("gpa") || t.contains("cgpa")) {
            return "grade_card";
        }
        return "other";
    }

    static int levenshtein(String a, String b) {
        int[][] m = new int[b.length() + 1][a.length() + 1];
        for (int i = 0; i <= b.length(); i++) m[i][0] = i;
        for (int j = 0; j <= a.length(); j++) m[0][j] = j;
        for (int i = 1; i <= b.length(); i++) {
            for (int j = 1; j <= a.length(); j++) {
                m[i][j] = b.charAt(i - 1) == a.charAt(j - 1) ? m[i - 1][j - 1]
                        : Math.min(m[i - 1][j - 1], Math.min(m[i][j - 1], m[i - 1][j])) + 1;
            }
        }
        return m[b.length()][a.length()];
    }

    static String correctSurname(String candidate, String text) {
        if (candidate == null || candidate.isEmpty()) return candidate;
        String father = "";
        for (String line : text.split("[\\n\\r]+")) {
            Matcher m = FATHER_LINE.matcher(line.trim());
            if (m.find()) {
                father = cleanNameLine(m.group(1));
                break;
            }
        }
        if (father.isEmpty()) return candidate;
        String[] c = candidate.split("\\s+");
        String[] f = father.split("\\s+");
        if (c.length < 2 || f.length < 2) return candidate;
        String cLast = c[c.length - 1].toLowerCase();
        String fLast = f[f.length - 1].toLowerCase();
        int dist = levenshtein(cLast, fLast);
        if (dist > 0 && dist <= 3 && cLast.substring(0, Math.min(2, cLast.length())).equals(fLast.substring(0, Math.min(2, fLast.length())))) {
            c[c.length - 1] = f[f.length - 1];
            return String.join(" ", c);
        }
        return candidate;
    }
}
