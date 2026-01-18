import { describe, expect, it, beforeEach, afterEach } from 'bun:test'
import { MemorySessionHandler, FileSessionHandler, CookieSessionHandler } from '../src/session/handlers'
import { SessionManager, createSession } from '../src/session/session'

describe('Session Module', () => {
  describe('MemorySessionHandler', () => {
    let handler: MemorySessionHandler

    beforeEach(async () => {
      handler = new MemorySessionHandler()
      await handler.open('', 'test')
    })

    afterEach(async () => {
      handler.clear()
    })

    it('should write and read session data', async () => {
      await handler.write('session-1', JSON.stringify({ userId: '123' }))

      const data = await handler.read('session-1')
      expect(JSON.parse(data)).toEqual({ userId: '123' })
    })

    it('should return empty string for non-existent session', async () => {
      const data = await handler.read('non-existent')
      expect(data).toBe('')
    })

    it('should destroy a session', async () => {
      await handler.write('session-2', JSON.stringify({ data: 'test' }))
      await handler.destroy('session-2')

      const data = await handler.read('session-2')
      expect(data).toBe('')
    })

    it('should get session count', async () => {
      await handler.write('session-a', '{}')
      await handler.write('session-b', '{}')
      await handler.write('session-c', '{}')

      expect(handler.getSessionCount()).toBe(3)
    })

    it('should clear all sessions', async () => {
      await handler.write('session-x', '{}')
      await handler.write('session-y', '{}')

      handler.clear()

      expect(handler.getSessionCount()).toBe(0)
    })

    it('should perform garbage collection', async () => {
      await handler.write('recent', '{}')
      const count = await handler.gc(0)
      expect(count).toBeGreaterThanOrEqual(0)
    })

    it('should close handler', async () => {
      const result = await handler.close()
      expect(result).toBe(true)
    })
  })

  describe('CookieSessionHandler', () => {
    let handler: CookieSessionHandler

    beforeEach(async () => {
      handler = new CookieSessionHandler()
      await handler.open('', 'test')
    })

    it('should set and get cookie data', async () => {
      handler.setCookieData(JSON.stringify({ user: 'test' }))

      const data = handler.getCookieData()
      expect(JSON.parse(data)).toEqual({ user: 'test' })
    })

    it('should write and read session', async () => {
      await handler.write('cookie-session', JSON.stringify({ value: 42 }))

      const data = await handler.read('cookie-session')
      expect(JSON.parse(data)).toEqual({ value: 42 })
    })

    it('should destroy session', async () => {
      await handler.write('cookie-session', '{"data": true}')
      await handler.destroy('cookie-session')

      const data = await handler.read('cookie-session')
      expect(data).toBe('')
    })

    it('should handle gc (no-op for cookies)', async () => {
      const count = await handler.gc(3600)
      expect(count).toBe(0)
    })
  })

  describe('SessionManager', () => {
    let manager: SessionManager

    beforeEach(() => {
      manager = createSession({
        driver: 'memory',
        cookie: 'test_session',
        lifetime: 120,
      })
    })

    it('should start a session', async () => {
      const result = await manager.start()

      expect(result).toBe(true)
      expect(manager.getId()).toBeDefined()
      expect(manager.getId().length).toBeGreaterThan(0)
    })

    it('should put and get session values', async () => {
      await manager.start()

      manager.put('user_id', '123')
      manager.put('role', 'admin')

      expect(manager.get('user_id')).toBe('123')
      expect(manager.get('role')).toBe('admin')
    })

    it('should return default for missing key', async () => {
      await manager.start()

      expect(manager.get('missing', 'default')).toBe('default')
    })

    it('should check if key exists', async () => {
      await manager.start()

      manager.put('exists', true)

      expect(manager.has('exists')).toBe(true)
      expect(manager.has('missing')).toBe(false)
    })

    it('should forget a key', async () => {
      await manager.start()

      manager.put('temp', 'value')
      manager.forget('temp')

      expect(manager.has('temp')).toBe(false)
    })

    it('should get all session data', async () => {
      await manager.start()

      manager.put('a', 1)
      manager.put('b', 2)

      const all = manager.all()
      expect(all.a).toBe(1)
      expect(all.b).toBe(2)
    })

    it('should flush all session data', async () => {
      await manager.start()

      manager.put('x', 'y')
      manager.flush()

      expect(manager.all()).toEqual({})
    })

    it('should regenerate session ID', async () => {
      await manager.start()
      const oldId = manager.getId()

      await manager.regenerate()
      const newId = manager.getId()

      expect(newId).not.toBe(oldId)
    })

    it('should pull value (get and remove)', async () => {
      await manager.start()
      manager.put('pullable', 'value')

      const value = manager.pull('pullable')
      expect(value).toBe('value')
      expect(manager.has('pullable')).toBe(false)
    })

    it('should flash session data', async () => {
      await manager.start()

      manager.flash('message', 'Hello!')

      expect(manager.get('message')).toBe('Hello!')
    })

    it('should handle CSRF token', async () => {
      await manager.start()

      const token = manager.token()
      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(token.length).toBeGreaterThan(0)
    })

    it('should regenerate CSRF token', async () => {
      await manager.start()

      const oldToken = manager.token()
      const newToken = manager.regenerateToken()

      expect(newToken).not.toBe(oldToken)
      expect(manager.token()).toBe(newToken)
    })

    it('should invalidate session', async () => {
      await manager.start()
      const oldId = manager.getId()
      manager.put('data', 'value')

      await manager.invalidate()

      expect(manager.getId()).not.toBe(oldId)
      expect(manager.all()).toEqual({})
    })

    it('should save session', async () => {
      await manager.start()
      manager.put('persistent', 'data')

      // Should not throw
      await manager.save()
    })

    it('should get cookie options', async () => {
      const options = manager.getCookieOptions()

      expect(options.name).toBe('test_session')
      expect(options.path).toBe('/')
      expect(options.secure).toBe(true)
      expect(options.httpOnly).toBe(true)
      expect(options.sameSite).toBe('lax')
    })

    it('should set session ID', async () => {
      const customId = 'custom-session-id-12345'
      manager.setId(customId)

      expect(manager.getId()).toBe(customId)
    })
  })
})
