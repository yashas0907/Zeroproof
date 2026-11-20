package com.zeroproof.config;

import com.zeroproof.service.LegacyImporter;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

/** Runs the legacy import at startup when ZEROPROOF_IMPORT_LEGACY=true. Safe to run repeatedly. */
@Component
@ConditionalOnProperty(name = "zeroproof.import-legacy", havingValue = "true")
public class LegacyImportRunner implements ApplicationRunner {
    private final LegacyImporter importer;
    private final AppProperties props;

    public LegacyImportRunner(LegacyImporter importer, AppProperties props) {
        this.importer = importer;
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Path data = Path.of(props.dataDir());
        importer.importFrom(data, data.resolve("java").resolve("legacy-import-report.json"));
    }
}
