/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

/**
 * This function serves files from the quarantine directory.
 * The fix addresses several security issues:
 * 1. Adds authentication check to ensure only authenticated users can access files.
 * 2. Improves input validation to prevent directory traversal attacks.
 * 3. Uses path.normalize and path.join for safer path handling.
 * 4. Ensures the requested file is within the quarantine directory to prevent unauthorized access.
 */
module.exports = function serveQuarantineFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Authentication check
    if (!req.session.user) {
      res.status(401)
      return next(new Error('Authentication required'))
    }

    const file = req.params.file

    // Improved input validation
    if (!file || typeof file !== 'string' || file.includes('..')) {
      res.status(400)
      return next(new Error('Invalid file name'))
    }

    // Use path.join and normalize the path
    const filePath = path.normalize(path.join(path.resolve('ftp/quarantine'), file))

    // Ensure the file is within the quarantine directory
    if (!filePath.startsWith(path.resolve('ftp/quarantine'))) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    res.sendFile(filePath)
  }
}
