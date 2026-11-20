package com.zeroproof.service;

import com.zeroproof.config.AppProperties;
import net.sourceforge.tess4j.Tesseract;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Turns an uploaded file into text: PDFBox for PDFs, Tess4J OCR for images (and scanned PDFs).
 * Any OCR failure (including a missing native library) degrades to empty text, which the
 * analyzer reports as UNREADABLE so the UI falls back to manual entry.
 */
@Service
public class TextExtractor {
    private static final Logger log = LoggerFactory.getLogger(TextExtractor.class);

    private final AppProperties props;
    private final Object ocrLock = new Object();
    private Tesseract tesseract;
    private boolean ocrUnavailable;

    public TextExtractor(AppProperties props) {
        this.props = props;
    }

    public String extract(byte[] data, String mimeType) {
        boolean pdf = "application/pdf".equals(mimeType) || (data.length > 4 && data[0] == 0x25 && data[1] == 0x50);
        if (pdf) {
            try (PDDocument doc = Loader.loadPDF(data)) {
                String text = new PDFTextStripper().getText(doc);
                if (text != null && text.trim().length() >= 5) {
                    return text;
                }
                if (doc.getNumberOfPages() > 0) {
                    return ocr(new PDFRenderer(doc).renderImageWithDPI(0, 200));
                }
            } catch (Exception e) {
                log.warn("PDF text extraction failed: {}", e.getMessage());
            }
            return "";
        }
        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(data));
            return img == null ? "" : ocr(img);
        } catch (Exception e) {
            log.warn("Image decoding failed: {}", e.getMessage());
            return "";
        }
    }

    private String ocr(BufferedImage image) {
        synchronized (ocrLock) {
            if (ocrUnavailable) return "";
            try {
                if (tesseract == null) {
                    Path dir = Path.of(props.tessdataDir()).toAbsolutePath().normalize();
                    if (!Files.exists(dir.resolve("eng.traineddata"))) {
                        throw new IllegalStateException("eng.traineddata not found in " + dir);
                    }
                    Tesseract t = new Tesseract();
                    t.setDatapath(dir.toString());
                    t.setLanguage("eng");
                    tesseract = t;
                }
                String text = tesseract.doOCR(image);
                return text == null ? "" : text;
            } catch (Throwable e) { // includes UnsatisfiedLinkError from the native library
                log.warn("OCR unavailable or failed ({}); falling back to manual entry", e.toString());
                if (e instanceof UnsatisfiedLinkError || e instanceof IllegalStateException || e instanceof NoClassDefFoundError) {
                    ocrUnavailable = true;
                }
                return "";
            }
        }
    }
}
