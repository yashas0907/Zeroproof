package com.zeroproof.service;

import java.time.Year;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Maps raw PLONK public signals to named fields and sanity-checks them. */
public final class ProofSignals {
    private ProofSignals() { }

    public static Map<String, String> named(String circuit, List<String> signals) {
        List<String> names = ZkpService.SIGNALS.get(circuit);
        if (names == null) {
            throw new IllegalArgumentException("Unknown circuit " + circuit);
        }
        if (signals.size() != names.size()) {
            throw new IllegalArgumentException(circuit + " expects " + names.size() + " public signals, got " + signals.size());
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < names.size(); i++) {
            out.put(names.get(i), signals.get(i));
        }
        return out;
    }

    /** The proof's currentYear must be within one year of the real year (server-enforced time). */
    public static boolean currentYearPlausible(Map<String, String> signals) {
        try {
            return Math.abs(Integer.parseInt(signals.get("currentYear")) - Year.now().getValue()) <= 1;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
