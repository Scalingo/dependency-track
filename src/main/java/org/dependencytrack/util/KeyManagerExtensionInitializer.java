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

import alpine.common.logging.Logger;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

/**
 * Initializes the KeyManager extension to support loading secret keys from environment variables.
 * This listener should execute before other initializers that may use encryption/decryption.
 *
 * @since 4.12.0
 */
public class KeyManagerExtensionInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KeyManagerExtensionInitializer.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing KeyManager extension for environment variable support");
        try {
            KeyManagerExtension.initialize();
            LOGGER.info("KeyManager extension initialized successfully");
        } catch (Exception e) {
            LOGGER.error("Failed to initialize KeyManager extension", e);
            // Don't throw the exception to allow the application to start with file-based key
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }
}
