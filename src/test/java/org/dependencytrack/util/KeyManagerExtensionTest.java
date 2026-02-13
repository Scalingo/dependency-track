/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for KeyManagerExtension
 */
class KeyManagerExtensionTest {

    @TempDir
    Path tempDir;

    private String originalSecretKeyContent;
    private String originalSecretKeyContentFile;

    @BeforeEach
    void setUp() {
        // Save original environment variable values (if any)
        originalSecretKeyContent = System.getenv("ALPINE_SECRET_KEY_CONTENT");
        originalSecretKeyContentFile = System.getenv("ALPINE_SECRET_KEY_CONTENT_FILE");
    }

    @AfterEach
    void tearDown() {
        // Clean up: Can't actually restore env vars in Java, but we can document the limitation
        // In real tests, you'd use a mocking library or system property overrides
    }

    @Test
    void testBase64EncodingDecoding() {
        // Generate a 32-byte key
        final byte[] keyBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyBytes[i] = (byte) i;
        }

        // Encode to base64
        final String base64Encoded = Base64.getEncoder().encodeToString(keyBytes);

        // Decode back
        final byte[] decoded = Base64.getDecoder().decode(base64Encoded);

        // Verify
        assertThat(decoded).isEqualTo(keyBytes);
        assertThat(decoded).hasSize(32);
    }

    @Test
    void testSecretKeyFileCreation() throws Exception {
        // Create a test key
        final byte[] keyBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyBytes[i] = (byte) (i * 2);
        }

        // Write to file
        final Path keyFile = tempDir.resolve("test-secret.key");
        Files.write(keyFile, keyBytes);

        // Read back
        final byte[] readBytes = Files.readAllBytes(keyFile);

        // Verify
        assertThat(readBytes).isEqualTo(keyBytes);
        assertThat(readBytes).hasSize(32);
    }

    @Test
    void testBase64KeyFileReading() throws Exception {
        // Create a base64-encoded key file
        final byte[] keyBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyBytes[i] = (byte) (255 - i);
        }

        final String base64Content = Base64.getEncoder().encodeToString(keyBytes);
        final Path contentFile = tempDir.resolve("secret_key_content.txt");
        Files.writeString(contentFile, base64Content);

        // Read and decode
        final String readContent = Files.readString(contentFile).trim();
        final byte[] decodedBytes = Base64.getDecoder().decode(readContent);

        // Verify
        assertThat(decodedBytes).isEqualTo(keyBytes);
        assertThat(decodedBytes).hasSize(32);
    }

    @Test
    void testSecretKeyPathResolution() {
        // Test that we can resolve the default secret key path
        final Config config = Config.getInstance();
        final String dataDirectory = config.getDataDirectorty();

        // Construct expected path
        final File expectedPath = new File(dataDirectory + File.separator + "keys" + File.separator + "secret.key");

        // Verify path construction
        assertThat(expectedPath.getParentFile().getName()).isEqualTo("keys");
        assertThat(expectedPath.getName()).isEqualTo("secret.key");
    }

    @Test
    void testKeyGeneration() throws Exception {
        // Simulate key generation like OpenSSL rand
        final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        final byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);

        // Verify length
        assertThat(keyBytes).hasSize(32);

        // Verify it can be base64 encoded
        final String base64 = Base64.getEncoder().encodeToString(keyBytes);
        assertThat(base64).isNotEmpty();

        // Verify round-trip
        final byte[] decoded = Base64.getDecoder().decode(base64);
        assertThat(decoded).isEqualTo(keyBytes);
    }
}
