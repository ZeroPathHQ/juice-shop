/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

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
