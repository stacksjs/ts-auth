import { describe, expect, it, beforeEach, afterEach } from 'bun:test'
import {
  AuditLogger,
  MemoryAuditLogStorage,
  ConsoleAuditLogStorage,
  CallbackAuditLogStorage,
  createAuditLogger,
} from '../src/audit'
import type { AuditLogEntry } from '../src/audit'

describe('Audit Logging Module', () => {
  describe('MemoryAuditLogStorage', () => {
    let storage: MemoryAuditLogStorage

    beforeEach(() => {
      storage = new MemoryAuditLogStorage({ maxEntries: 100 })
    })

    afterEach(async () => {
      await storage.close()
    })

    it('should store audit entries', async () => {
      const entry: AuditLogEntry = {
        id: 'test-1',
        timestamp: new Date(),
        event: 'login.success',
        userId: '123',
        success: true,
      }

      await storage.store(entry)

      const entries = await storage.query({})
      expect(entries.length).toBe(1)
      expect(entries[0].id).toBe('test-1')
    })

    it('should respect max entries limit', async () => {
      const limitedStorage = new MemoryAuditLogStorage({ maxEntries: 3 })

      for (let i = 0; i < 5; i++) {
        await limitedStorage.store({
          id: `entry-${i}`,
          timestamp: new Date(),
          event: 'login.attempt',
          success: false,
        })
      }

      const entries = await limitedStorage.query({})
      expect(entries.length).toBe(3)
      // Should keep the most recent entries (newest first)
      expect(entries.some(e => e.id === 'entry-4')).toBe(true)
      expect(entries.some(e => e.id === 'entry-0')).toBe(false)

      await limitedStorage.close()
    })

    it('should query by event type', async () => {
      await storage.store({
        id: 'login-1',
        timestamp: new Date(),
        event: 'login.success',
        success: true,
      })
      await storage.store({
        id: 'logout-1',
        timestamp: new Date(),
        event: 'logout',
        success: true,
      })

      const entries = await storage.query({ events: ['login.success'] })
      expect(entries.length).toBe(1)
      expect(entries[0].id).toBe('login-1')
    })

    it('should query by user ID', async () => {
      await storage.store({
        id: 'user1-event',
        timestamp: new Date(),
        event: 'login.success',
        userId: 'user-1',
        success: true,
      })
      await storage.store({
        id: 'user2-event',
        timestamp: new Date(),
        event: 'login.success',
        userId: 'user-2',
        success: true,
      })

      const entries = await storage.query({ userId: 'user-1' })
      expect(entries.length).toBe(1)
      expect(entries[0].userId).toBe('user-1')
    })

    it('should query by time range', async () => {
      const now = new Date()
      const hourAgo = new Date(now.getTime() - 3600000)
      const twoHoursAgo = new Date(now.getTime() - 7200000)

      await storage.store({
        id: 'old-event',
        timestamp: twoHoursAgo,
        event: 'login.success',
        success: true,
      })
      await storage.store({
        id: 'recent-event',
        timestamp: now,
        event: 'login.success',
        success: true,
      })

      const entries = await storage.query({ from: hourAgo })
      expect(entries.length).toBe(1)
      expect(entries[0].id).toBe('recent-event')
    })

    it('should query by success status', async () => {
      await storage.store({
        id: 'success-event',
        timestamp: new Date(),
        event: 'login.success',
        success: true,
      })
      await storage.store({
        id: 'failure-event',
        timestamp: new Date(),
        event: 'login.failure',
        success: false,
      })

      const failures = await storage.query({ success: false })
      expect(failures.length).toBe(1)
      expect(failures[0].id).toBe('failure-event')
    })

    it('should count entries', async () => {
      await storage.store({
        id: 'event-1',
        timestamp: new Date(),
        event: 'login.success',
        success: true,
      })
      await storage.store({
        id: 'event-2',
        timestamp: new Date(),
        event: 'login.failure',
        success: false,
      })

      const count = await storage.count()
      expect(count).toBe(2)
    })

    it('should get entry by ID', async () => {
      await storage.store({
        id: 'specific-entry',
        timestamp: new Date(),
        event: 'login.success',
        success: true,
      })

      const entry = await storage.get('specific-entry')
      expect(entry).not.toBeNull()
      expect(entry?.id).toBe('specific-entry')
    })

    it('should return null for non-existent entry', async () => {
      const entry = await storage.get('non-existent')
      expect(entry).toBeNull()
    })

    it('should delete old entries', async () => {
      const now = new Date()
      const oldDate = new Date(now.getTime() - 7200000) // 2 hours ago

      await storage.store({
        id: 'old-entry',
        timestamp: oldDate,
        event: 'login.success',
        success: true,
      })
      await storage.store({
        id: 'new-entry',
        timestamp: now,
        event: 'login.success',
        success: true,
      })

      const deleted = await storage.deleteOlderThan(new Date(now.getTime() - 3600000))
      expect(deleted).toBe(1)

      const remaining = await storage.query({})
      expect(remaining.length).toBe(1)
      expect(remaining[0].id).toBe('new-entry')
    })
  })

  describe('CallbackAuditLogStorage', () => {
    it('should call the callback with entries', async () => {
      const entries: AuditLogEntry[] = []
      const storage = new CallbackAuditLogStorage(async (entry) => {
        entries.push(entry)
      })

      await storage.store({
        id: 'callback-1',
        timestamp: new Date(),
        event: 'login.success',
        success: true,
      })

      expect(entries.length).toBe(1)
      expect(entries[0].id).toBe('callback-1')

      await storage.close()
    })
  })

  describe('AuditLogger', () => {
    let logger: AuditLogger

    beforeEach(() => {
      logger = createAuditLogger()
    })

    afterEach(async () => {
      await logger.close()
    })

    it('should log authentication events', async () => {
      await logger.log('login.success', {
        userId: '123',
        success: true,
      })

      const entries = await logger.query({ events: ['login.success'] })
      expect(entries.length).toBe(1)
      expect(entries[0].userId).toBe('123')
    })

    it('should log with metadata', async () => {
      await logger.log('login.attempt', {
        success: false,
        metadata: {
          email: 'user@example.com',
          reason: 'invalid_password',
        },
      })

      const entries = await logger.query({ events: ['login.attempt'] })
      expect(entries[0].metadata?.reason).toBe('invalid_password')
    })

    it('should log with IP address', async () => {
      await logger.log('login.success', {
        userId: '123',
        success: true,
        ipAddress: '192.168.1.1',
      })

      const entries = await logger.query({})
      expect(entries[0].ipAddress).toBe('192.168.1.1')
    })

    it('should log with user agent', async () => {
      await logger.log('login.success', {
        userId: '123',
        success: true,
        userAgent: 'Mozilla/5.0',
      })

      const entries = await logger.query({})
      expect(entries[0].userAgent).toBe('Mozilla/5.0')
    })

    it('should use convenience method for login success', async () => {
      await logger.logLoginSuccess('user-123')

      const entries = await logger.query({ events: ['login.success'] })
      expect(entries.length).toBe(1)
      expect(entries[0].userId).toBe('user-123')
    })

    it('should use convenience method for login failure', async () => {
      await logger.logLoginFailure('user-456', 'Invalid password')

      const entries = await logger.query({ events: ['login.failure'] })
      expect(entries.length).toBe(1)
      expect(entries[0].error).toBe('Invalid password')
    })

    it('should use convenience method for logout', async () => {
      await logger.logLogout('user-789')

      const entries = await logger.query({ events: ['logout'] })
      expect(entries.length).toBe(1)
      expect(entries[0].userId).toBe('user-789')
    })

    it('should use convenience method for token events', async () => {
      await logger.logTokenIssued('user-123', 'access')

      const entries = await logger.query({ events: ['token.issued'] })
      expect(entries.length).toBe(1)
      expect(entries[0].metadata?.tokenType).toBe('access')
    })

    it('should get user activity', async () => {
      await logger.logLoginSuccess('user-abc')
      await logger.logLogout('user-abc')
      await logger.logLoginSuccess('other-user')

      const activity = await logger.getUserActivity('user-abc')
      expect(activity.length).toBe(2)
      expect(activity.every(e => e.userId === 'user-abc')).toBe(true)
    })

    it('should get failed logins', async () => {
      await logger.logLoginSuccess('user-test')
      await logger.logLoginFailure('user-test', 'Wrong password')
      await logger.logLoginFailure('user-test', 'Account locked')

      const failures = await logger.getFailedLogins('user-test')
      expect(failures.length).toBe(2)
    })

    it('should get security events', async () => {
      await logger.logRateLimited('user@example.com', '/login')
      await logger.logAccountLocked('user-123')

      const securityEvents = await logger.getSecurityEvents()
      expect(securityEvents.length).toBe(2)
    })
  })
})
