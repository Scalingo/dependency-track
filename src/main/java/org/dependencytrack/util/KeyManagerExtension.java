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
import alpine.common.logging.Logger;
import alpine.security.crypto.KeyManager;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Extension for KeyManager to support loading secret key from environment variable content.
 * This allows passing the secret key content directly via environment variable instead of
 * only supporting file path references.
 *
 * @since 4.12.0
 */
public class KeyManagerExtension {

    private static final Logger LOGGER = Logger.getLogger(KeyManagerExtension.class);
    private static final String SECRET_KEY_CONTENT_ENV = "ALPINE_SECRET_KEY_CONTENT";
    private static final String SECRET_KEY_CONTENT_FILE_ENV = "ALPINE_SECRET_KEY_CONTENT_FILE";
    private static boolean initialized = false;

    /**
     * Initialize the KeyManager extension to support loading secret key from environment variable.
     * This should be called early during application startup, before KeyManager is first accessed.
     */
    public static synchronized void initialize() {
        if (initialized) {
            return;
        }

        try {
            final String secretKeyContent = getSecretKeyContent();
            
            if (secretKeyContent != null && !secretKeyContent.isEmpty()) {
                LOGGER.info("Loading secret key from environment variable content");
                
                // Decode the base64-encoded key content
                final byte[] keyBytes = Base64.getDecoder().decode(secretKeyContent);
                final SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
                
                // Get the secret key path where it should be stored
                final File keyFile = getSecretKeyPath();
                
                // Ensure parent directory exists
                keyFile.getParentFile().mkdirs();
                
                // Write the key to the file if it doesn't exist or is different
                boolean shouldWrite = !keyFile.exists();
                
                if (!shouldWrite && keyFile.exists()) {
                    // Check if the existing key is different
                    try (InputStream fis = Files.newInputStream(keyFile.toPath())) {
                        final byte[] existingKeyBytes = fis.readAllBytes();
                        shouldWrite = !java.util.Arrays.equals(keyBytes, existingKeyBytes);
                    } catch (Exception e) {
                        LOGGER.debug("Error reading existing key file, will overwrite", e);
                        shouldWrite = true;
                    }
                }
                
                if (shouldWrite) {
                    LOGGER.info("Writing secret key to " + keyFile.getAbsolutePath());
                    try (OutputStream fos = Files.newOutputStream(keyFile.toPath())) {
                        fos.write(keyBytes);
                    }
                    
                    // Force KeyManager to reload the key
                    reloadKeyManager();
                }
                
                LOGGER.info("Secret key loaded successfully from environment variable");
            }
            
            initialized = true;
        } catch (Exception e) {
            LOGGER.error("Failed to initialize KeyManager extension", e);
            throw new RuntimeException("Failed to initialize KeyManager extension", e);
        }
    }

    /**
     * Gets the secret key content from environment variable or file.
     * First checks ALPINE_SECRET_KEY_CONTENT_FILE, then ALPINE_SECRET_KEY_CONTENT.
     *
     * @return the secret key content (base64-encoded) or null if not found
     */
    private static String getSecretKeyContent() {
        // First check if a file path is provided in ALPINE_SECRET_KEY_CONTENT_FILE
        final String contentFilePath = System.getenv(SECRET_KEY_CONTENT_FILE_ENV);
        if (contentFilePath != null && !contentFilePath.isEmpty()) {
            try {
                final String content = Files.readString(Paths.get(contentFilePath)).trim();
                LOGGER.info("Secret key content loaded from file: " + contentFilePath);
                return content;
            } catch (IOException e) {
                LOGGER.error("Failed to read secret key content from file: " + contentFilePath, e);
                throw new RuntimeException("Failed to read secret key content from file", e);
            }
        }

        // Otherwise check direct environment variable
        final String content = System.getenv(SECRET_KEY_CONTENT_ENV);
        if (content != null && !content.isEmpty()) {
            LOGGER.info("Secret key content loaded from environment variable");
            return content.trim();
        }

        return null;
    }

    /**
     * Gets the path where the secret key should be stored.
     *
     * @return File representing the secret key path
     */
    private static File getSecretKeyPath() {
        final String secretKeyPath = Config.getInstance().getProperty(Config.AlpineKey.SECRET_KEY_PATH);
        if (secretKeyPath != null) {
            return Paths.get(secretKeyPath).toFile();
        }
        return new File(Config.getInstance().getDataDirectorty()
                + File.separator
                + "keys" + File.separator
                + "secret.key");
    }

    /**
     * Forces the KeyManager singleton to reload its secret key.
     * Uses reflection to access private methods.
     */
    private static void reloadKeyManager() {
        try {
            final KeyManager keyManager = KeyManager.getInstance();
            
            // Reset the secretKey field to null
            final Field secretKeyField = KeyManager.class.getDeclaredField("secretKey");
            secretKeyField.setAccessible(true);
            secretKeyField.set(keyManager, null);
            
            // Call the private initialize() method to reload the key
            final Method initializeMethod = KeyManager.class.getDeclaredMethod("initialize");
            initializeMethod.setAccessible(true);
            initializeMethod.invoke(keyManager);
            
            LOGGER.info("KeyManager reloaded successfully");
        } catch (Exception e) {
            LOGGER.warn("Failed to reload KeyManager, will be loaded on next access", e);
        }
    }
}
