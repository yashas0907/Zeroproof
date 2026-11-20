package com.zeroproof.controller;

import com.zeroproof.api.ApiException;
import com.zeroproof.api.ApiResponse;
import com.zeroproof.entity.DocumentEntity;
import com.zeroproof.service.DocumentService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v3/documents")
public class DocumentController {
    private final DocumentService documents;

    public DocumentController(DocumentService documents) {
        this.documents = documents;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> upload(
            @RequestParam(value = "document", required = false) MultipartFile file,
            @RequestParam(value = "fullName", required = false) String fullName,
            @RequestParam(value = "dateOfBirth", required = false) String dateOfBirth,
            @RequestParam(value = "documentType", required = false) String documentType) throws IOException {
        if (file == null || file.isEmpty()) {
            throw ApiException.badRequest("NO_FILE", "No document file provided.");
        }
        DocumentService.UploadResult r = documents.upload(file.getBytes(), file.getOriginalFilename(),
                file.getContentType(), fullName, dateOfBirth, documentType);
        DocumentEntity d = r.document();

        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("name", r.extracted().name().isEmpty() ? "UNKNOWN" : r.extracted().name());
        attrs.put("dob", r.extracted().dateOfBirth());
        attrs.put("documentType", r.extracted().documentType());
        attrs.put("status", r.extracted().status());
        attrs.put("reason", r.extracted().reason());

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("id", d.getId());
        doc.put("originalName", d.getOriginalName());
        doc.put("documentHash", d.getDocumentHash());
        doc.put("attributes", attrs);
        doc.put("duplicate", r.duplicate());
        doc.put("isVerified", d.isVerified());
        doc.put("createdAt", d.getCreatedAt().toString());
        return ApiResponse.created(Map.of("document", doc), "v3");
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> list() {
        List<Map<String, Object>> docs = documents.list().stream().map(DocumentController::summary).toList();
        return ApiResponse.ok(Map.of("documents", docs, "count", docs.size()), "v3");
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> get(@PathVariable String id) {
        DocumentEntity entity = documents.get(id);
        Map<String, Object> d = summary(entity);
        d.put("encryptionAlgorithm", entity.getEncryptionAlgorithm());
        return ApiResponse.ok(Map.of("document", d), "v3");
    }

    @GetMapping("/{id}/file")
    public ResponseEntity<byte[]> file(@PathVariable String id) {
        DocumentEntity d = documents.get(id);
        byte[] plain = documents.readDecrypted(d);
        MediaType type;
        try {
            type = MediaType.parseMediaType(d.getMimeType());
        } catch (RuntimeException e) {
            type = MediaType.APPLICATION_OCTET_STREAM;
        }
        String name = d.getOriginalName() == null ? "document" : d.getOriginalName().replaceAll("[^A-Za-z0-9._-]", "_");
        return ResponseEntity.ok()
                .contentType(type)
                .header("Content-Disposition", "attachment; filename=\"" + name + "\"")
                .header("X-Content-Type-Options", "nosniff")
                .header("Cache-Control", "no-store")
                .body(plain);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        documents.delete(id);
        return ApiResponse.ok(Map.of("deleted", true, "documentId", id), "v3");
    }

    private static Map<String, Object> summary(DocumentEntity d) {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("name", d.getFullName());
        attrs.put("fullName", d.getFullName());
        attrs.put("dob", d.getDateOfBirth());
        attrs.put("dateOfBirth", d.getDateOfBirth());
        attrs.put("documentType", d.getDocumentType());
        attrs.put("status", d.getExtractStatus());
        attrs.put("reason", d.getReason());

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", d.getId());
        m.put("originalName", d.getOriginalName());
        m.put("sizeBytes", d.getSizeBytes());
        m.put("documentHash", d.getDocumentHash());
        m.put("attributes", attrs);
        m.put("createdAt", d.getCreatedAt().toString());
        m.put("status", d.getStatus());
        return m;
    }
}
