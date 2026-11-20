package com.zeroproof;

import com.zeroproof.service.DocumentAnalyzer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AnalyzerTest {
    @Test
    void extractsLabelledNameAndDob() {
        var r = DocumentAnalyzer.analyze("Student Report\nName: Alice Tester\nDOB: 12/05/1990\n");
        assertEquals("Alice Tester", r.name());
        assertEquals("1990-05-12", r.dateOfBirth());
        assertEquals("SUCCESS", r.status());
    }

    @Test
    void parsesMultiLineDobAndIso() {
        var r = DocumentAnalyzer.analyze("Name: Bob Example\nDATE OF BIRTH:\n1985-03-09\n");
        assertEquals("1985-03-09", r.dateOfBirth());
    }

    @Test
    void ocrFixHandlesLettersInDigits() {
        assertEquals("1990-05-12", DocumentAnalyzer.analyze("Name: Carol Doe\nDOB: 12/O5/1990").dateOfBirth());
    }

    @Test
    void unreadableTextIsReportedNotInvented() {
        var r = DocumentAnalyzer.analyze("  ");
        assertEquals("UNREADABLE", r.status());
        assertEquals("", r.name());
        assertEquals("", r.dateOfBirth());
    }

    @Test
    void noPersonDataIsFabricatedForUnknownText() {
        var r = DocumentAnalyzer.analyze("Some random invoice text with no identity information at all");
        assertEquals("NO_DATA_FOUND", r.status());
        assertEquals("", r.name());
    }

    @Test
    void registryHealingIsNotApplied() {
        // Legacy code replaced extracted values when a known Aadhaar number appeared; that must not happen.
        var r = DocumentAnalyzer.analyze("Government of India\nName: Rahul Verma\nDOB: 01/01/2000\n954050020568");
        assertEquals("Rahul Verma", r.name());
        assertEquals("2000-01-01", r.dateOfBirth());
    }
}
