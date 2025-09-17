const { v4: uuidv4 } = require('uuid')
const crypto = require('crypto')
const ProxyHelper = require('../utils/proxyHelper')
const axios = require('axios')
const redis = require('../models/redis')
const config = require('../../config/config')
const logger = require('../utils/logger')
const { maskToken } = require('../utils/tokenMask')
const {
  logRefreshStart,
  logRefreshSuccess,
  logRefreshError,
  logTokenUsage,
  logRefreshSkipped
} = require('../utils/tokenRefreshLogger')
const tokenRefreshService = require('./tokenRefreshService')
const LRUCache = require('../utils/lruCache')
const { formatDateWithTimezone, getISOStringWithTimezone } = require('../utils/dateHelper')

class ClaudeAccountService {
  constructor() {
    this.claudeApiUrl = 'https://console.anthropic.com/v1/oauth/token'
    this.claudeOauthClientId = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'
    let maxWarnings = parseInt(process.env.CLAUDE_5H_WARNING_MAX_NOTIFICATIONS || '', 10)

    if (Number.isNaN(maxWarnings) && config.claude?.fiveHourWarning) {
      maxWarnings = parseInt(config.claude.fiveHourWarning.maxNotificationsPerWindow, 10)
    }

    if (Number.isNaN(maxWarnings) || maxWarnings < 1) {
      maxWarnings = 1
    }

    this.maxFiveHourWarningsPerWindow = Math.min(maxWarnings, 10)

    // 加密相关常量
    this.ENCRYPTION_ALGORITHM = 'aes-256-cbc'
    this.ENCRYPTION_SALT = 'salt'

    // 🚀 性能优化：缓存派生的加密密钥，避免每次重复计算
    // scryptSync 是 CPU 密集型操作，缓存可以减少 95%+ 的 CPU 占用
    this._encryptionKeyCache = null

    // 🔄 解密结果缓存，提高解密性能
    this._decryptCache = new LRUCache(500)

    // 🧹 定期清理缓存（每10分钟）
    setInterval(
      () => {
        this._decryptCache.cleanup()
        logger.info('🧹 Claude decrypt cache cleanup completed', this._decryptCache.getStats())
      },
      10 * 60 * 1000
    )
  }

  // 🏢 创建Claude账户
  async createAccount(options = {}) {
    const {
      name = 'Unnamed Account',
      description = '',
      email = '',
      password = '',
      refreshToken = '',
      claudeAiOauth = null, // Claude标准格式的OAuth数据
      proxy = null, // { type: 'socks5', host: 'localhost', port: 1080, username: '', password: '' }
      isActive = true,
      accountType = 'shared', // 'dedicated' or 'shared'
      platform = 'claude',
      priority = 50, // 调度优先级 (1-100，数字越小优先级越高)
      schedulable = true, // 是否可被调度
      subscriptionInfo = null, // 手动设置的订阅信息
      autoStopOnWarning = false, // 5小时使用量接近限制时自动停止调度
      useUnifiedUserAgent = false, // 是否使用统一Claude Code版本的User-Agent
      useUnifiedClientId = false, // 是否使用统一的客户端标识
      unifiedClientId = '' // 统一的客户端标识
    } = options

    const accountId = uuidv4()

    let accountData

    if (claudeAiOauth) {
      // 使用Claude标准格式的OAuth数据
      accountData = {
        id: accountId,
        name,
        description,
        email: this._encryptSensitiveData(email),
        password: this._encryptSensitiveData(password),
        claudeAiOauth: this._encryptSensitiveData(JSON.stringify(claudeAiOauth)),
        accessToken: this._encryptSensitiveData(claudeAiOauth.accessToken),
        refreshToken: this._encryptSensitiveData(claudeAiOauth.refreshToken),
        expiresAt: claudeAiOauth.expiresAt.toString(),
        scopes: claudeAiOauth.scopes.join(' '),
        proxy: proxy ? JSON.stringify(proxy) : '',
        isActive: isActive.toString(),
        accountType, // 账号类型：'dedicated' 或 'shared' 或 'group'
        platform,
        priority: priority.toString(), // 调度优先级
        createdAt: new Date().toISOString(),
        lastUsedAt: '',
        lastRefreshAt: '',
        status: 'active', // 有OAuth数据的账户直接设为active
        errorMessage: '',
        schedulable: schedulable.toString(), // 是否可被调度
        autoStopOnWarning: autoStopOnWarning.toString(), // 5小时使用量接近限制时自动停止调度
        useUnifiedUserAgent: useUnifiedUserAgent.toString(), // 是否使用统一Claude Code版本的User-Agent
        useUnifiedClientId: useUnifiedClientId.toString(), // 是否使用统一的客户端标识
        unifiedClientId: unifiedClientId || '', // 统一的客户端标识
        // 优先使用手动设置的订阅信息，否则使用OAuth数据中的，否则默认为空
        subscriptionInfo: subscriptionInfo
          ? JSON.stringify(subscriptionInfo)
          : claudeAiOauth.subscriptionInfo
            ? JSON.stringify(claudeAiOauth.subscriptionInfo)
            : ''
      }
    } else {
      // 兼容旧格式
      accountData = {
        id: accountId,
        name,
        description,
        email: this._encryptSensitiveData(email),
        password: this._encryptSensitiveData(password),
        refreshToken: this._encryptSensitiveData(refreshToken),
        accessToken: '',
        expiresAt: '',
        scopes: '',
        proxy: proxy ? JSON.stringify(proxy) : '',
        isActive: isActive.toString(),
        accountType, // 账号类型：'dedicated' 或 'shared' 或 'group'
        platform,
        priority: priority.toString(), // 调度优先级
        createdAt: new Date().toISOString(),
        lastUsedAt: '',
        lastRefreshAt: '',
        status: 'created', // created, active, expired, error
        errorMessage: '',
        schedulable: schedulable.toString(), // 是否可被调度
        autoStopOnWarning: autoStopOnWarning.toString(), // 5小时使用量接近限制时自动停止调度
        useUnifiedUserAgent: useUnifiedUserAgent.toString(), // 是否使用统一Claude Code版本的User-Agent
        // 手动设置的订阅信息
        subscriptionInfo: subscriptionInfo ? JSON.stringify(subscriptionInfo) : ''
      }
    }

    await redis.setClaudeAccount(accountId, accountData)

    logger.success(`🏢 Created Claude account: ${name} (${accountId})`)

    // 如果有 OAuth 数据和 accessToken，且包含 user:profile 权限，尝试获取 profile 信息
    if (claudeAiOauth && claudeAiOauth.accessToken) {
      // 检查是否有 user:profile 权限（标准 OAuth 有，Setup Token 没有）
      const hasProfileScope = claudeAiOauth.scopes && claudeAiOauth.scopes.includes('user:profile')

      if (hasProfileScope) {
        try {
          const agent = this._createProxyAgent(proxy)
          await this.fetchAndUpdateAccountProfile(accountId, claudeAiOauth.accessToken, agent)
          logger.info(`📊 Successfully fetched profile info for new account: ${name}`)
        } catch (profileError) {
          logger.warn(`⚠️ Failed to fetch profile info for new account: ${profileError.message}`)
        }
      } else {
        logger.info(`⏩ Skipping profile fetch for account ${name} (no user:profile scope)`)
      }
    }

    return {
      id: accountId,
      name,
      description,
      email,
      isActive,
      proxy,
      accountType,
      platform,
      priority,
      status: accountData.status,
      createdAt: accountData.createdAt,
      expiresAt: accountData.expiresAt,
      scopes: claudeAiOauth ? claudeAiOauth.scopes : [],
      autoStopOnWarning,
      useUnifiedUserAgent,
      useUnifiedClientId,
      unifiedClientId
    }
  }

  // 🔄 刷新Claude账户token
  async refreshAccountToken(accountId) {
    let lockAcquired = false

    try {
      const accountData = await redis.getClaudeAccount(accountId)

      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      const refreshToken = this._decryptSensitiveData(accountData.refreshToken)

      if (!refreshToken) {
        throw new Error('No refresh token available - manual token update required')
      }

      // 尝试获取分布式锁
      lockAcquired = await tokenRefreshService.acquireRefreshLock(accountId, 'claude')

      if (!lockAcquired) {
        // 如果无法获取锁，说明另一个进程正在刷新
        logger.info(
          `🔒 Token refresh already in progress for account: ${accountData.name} (${accountId})`
        )
        logRefreshSkipped(accountId, accountData.name, 'claude', 'already_locked')

        // 等待一段时间后返回，期望其他进程已完成刷新
        await new Promise((resolve) => setTimeout(resolve, 2000))

        // 重新获取账户数据（可能已被其他进程刷新）
        const updatedData = await redis.getClaudeAccount(accountId)
        if (updatedData && updatedData.accessToken) {
          const accessToken = this._decryptSensitiveData(updatedData.accessToken)
          return {
            success: true,
            accessToken,
            expiresAt: updatedData.expiresAt
          }
        }

        throw new Error('Token refresh in progress by another process')
      }

      // 记录开始刷新
      logRefreshStart(accountId, accountData.name, 'claude', 'manual_refresh')
      logger.info(`🔄 Starting token refresh for account: ${accountData.name} (${accountId})`)

      // 创建代理agent
      const agent = this._createProxyAgent(accountData.proxy)

      const response = await axios.post(
        this.claudeApiUrl,
        {
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: this.claudeOauthClientId
        },
        {
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json, text/plain, */*',
            'User-Agent': 'claude-cli/1.0.56 (external, cli)',
            'Accept-Language': 'en-US,en;q=0.9',
            Referer: 'https://claude.ai/',
            Origin: 'https://claude.ai'
          },
          httpsAgent: agent,
          timeout: 30000
        }
      )

      if (response.status === 200) {
        // 记录完整的响应数据到专门的认证详细日志
        logger.authDetail('Token refresh response', response.data)

        // 记录简化版本到主日志
        logger.info('📊 Token refresh response (analyzing for subscription info):', {
          status: response.status,
          hasData: !!response.data,
          dataKeys: response.data ? Object.keys(response.data) : []
        })

        const { access_token, refresh_token, expires_in } = response.data

        // 检查是否有套餐信息
        if (
          response.data.subscription ||
          response.data.plan ||
          response.data.tier ||
          response.data.account_type
        ) {
          const subscriptionInfo = {
            subscription: response.data.subscription,
            plan: response.data.plan,
            tier: response.data.tier,
            accountType: response.data.account_type,
            features: response.data.features,
            limits: response.data.limits
          }
          logger.info('🎯 Found subscription info in refresh response:', subscriptionInfo)

          // 将套餐信息存储在账户数据中
          accountData.subscriptionInfo = JSON.stringify(subscriptionInfo)
        }

        // 更新账户数据
        accountData.accessToken = this._encryptSensitiveData(access_token)
        accountData.refreshToken = this._encryptSensitiveData(refresh_token)
        accountData.expiresAt = (Date.now() + expires_in * 1000).toString()
        accountData.lastRefreshAt = new Date().toISOString()
        accountData.status = 'active'
        accountData.errorMessage = ''

        await redis.setClaudeAccount(accountId, accountData)

        // 刷新成功后，如果有 user:profile 权限，尝试获取账号 profile 信息
        // 检查账户的 scopes 是否包含 user:profile（标准 OAuth 有，Setup Token 没有）
        const hasProfileScope = accountData.scopes && accountData.scopes.includes('user:profile')

        if (hasProfileScope) {
          try {
            await this.fetchAndUpdateAccountProfile(accountId, access_token, agent)
          } catch (profileError) {
            logger.warn(`⚠️ Failed to fetch profile info after refresh: ${profileError.message}`)
          }
        } else {
          logger.debug(
            `⏩ Skipping profile fetch after refresh for account ${accountId} (no user:profile scope)`
          )
        }

        // 记录刷新成功
        logRefreshSuccess(accountId, accountData.name, 'claude', {
          accessToken: access_token,
          refreshToken: refresh_token,
          expiresAt: accountData.expiresAt,
          scopes: accountData.scopes
        })

        logger.success(
          `🔄 Refreshed token for account: ${accountData.name} (${accountId}) - Access Token: ${maskToken(access_token)}`
        )

        return {
          success: true,
          accessToken: access_token,
          expiresAt: accountData.expiresAt
        }
      } else {
        throw new Error(`Token refresh failed with status: ${response.status}`)
      }
    } catch (error) {
      // 记录刷新失败
      const accountData = await redis.getClaudeAccount(accountId)
      if (accountData) {
        logRefreshError(accountId, accountData.name, 'claude', error)
        accountData.status = 'error'
        accountData.errorMessage = error.message
        await redis.setClaudeAccount(accountId, accountData)

        // 发送Webhook通知
        try {
          const webhookNotifier = require('../utils/webhookNotifier')
          await webhookNotifier.sendAccountAnomalyNotification({
            accountId,
            accountName: accountData.name,
            platform: 'claude-oauth',
            status: 'error',
            errorCode: 'CLAUDE_OAUTH_ERROR',
            reason: `Token refresh failed: ${error.message}`
          })
        } catch (webhookError) {
          logger.error('Failed to send webhook notification:', webhookError)
        }
      }

      logger.error(`❌ Failed to refresh token for account ${accountId}:`, error)

      throw error
    } finally {
      // 释放锁
      if (lockAcquired) {
        await tokenRefreshService.releaseRefreshLock(accountId, 'claude')
      }
    }
  }

  // 🔍 获取账户信息
  async getAccount(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)

      if (!accountData || Object.keys(accountData).length === 0) {
        return null
      }

      return accountData
    } catch (error) {
      logger.error('❌ Failed to get Claude account:', error)
      return null
    }
  }

  // 🎯 获取有效的访问token
  async getValidAccessToken(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)

      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      if (accountData.isActive !== 'true') {
        throw new Error('Account is disabled')
      }

      // 检查token是否过期
      const expiresAt = parseInt(accountData.expiresAt)
      const now = Date.now()
      const isExpired = !expiresAt || now >= expiresAt - 60000 // 60秒提前刷新

      // 记录token使用情况
      logTokenUsage(accountId, accountData.name, 'claude', accountData.expiresAt, isExpired)

      if (isExpired) {
        logger.info(`🔄 Token expired/expiring for account ${accountId}, attempting refresh...`)
        try {
          const refreshResult = await this.refreshAccountToken(accountId)
          return refreshResult.accessToken
        } catch (refreshError) {
          logger.warn(`⚠️ Token refresh failed for account ${accountId}: ${refreshError.message}`)
          // 如果刷新失败，仍然尝试使用当前token（可能是手动添加的长期有效token）
          const currentToken = this._decryptSensitiveData(accountData.accessToken)
          if (currentToken) {
            logger.info(`🔄 Using current token for account ${accountId} (refresh failed)`)
            return currentToken
          }
          throw refreshError
        }
      }

      const accessToken = this._decryptSensitiveData(accountData.accessToken)

      if (!accessToken) {
        throw new Error('No access token available')
      }

      // 更新最后使用时间和会话窗口
      accountData.lastUsedAt = new Date().toISOString()
      await this.updateSessionWindow(accountId, accountData)
      await redis.setClaudeAccount(accountId, accountData)

      return accessToken
    } catch (error) {
      logger.error(`❌ Failed to get valid access token for account ${accountId}:`, error)
      throw error
    }
  }

  // 📋 获取所有Claude账户
  async getAllAccounts() {
    try {
      const accounts = await redis.getAllClaudeAccounts()

      // 处理返回数据，移除敏感信息并添加限流状态和会话窗口信息
      const processedAccounts = await Promise.all(
        accounts.map(async (account) => {
          // 获取限流状态信息
          const rateLimitInfo = await this.getAccountRateLimitInfo(account.id)

          // 获取会话窗口信息
          const sessionWindowInfo = await this.getSessionWindowInfo(account.id)

          return {
            id: account.id,
            name: account.name,
            description: account.description,
            email: account.email ? this._maskEmail(this._decryptSensitiveData(account.email)) : '',
            isActive: account.isActive === 'true',
            proxy: account.proxy ? JSON.parse(account.proxy) : null,
            status: account.status,
            errorMessage: account.errorMessage,
            accountType: account.accountType || 'shared', // 兼容旧数据，默认为共享
            priority: parseInt(account.priority) || 50, // 兼容旧数据，默认优先级50
            platform: account.platform || 'claude', // 添加平台标识，用于前端区分
            createdAt: account.createdAt,
            lastUsedAt: account.lastUsedAt,
            lastRefreshAt: account.lastRefreshAt,
            expiresAt: account.expiresAt,
            // 添加 scopes 字段用于判断认证方式
            // 处理空字符串的情况，避免返回 ['']
            scopes: account.scopes && account.scopes.trim() ? account.scopes.split(' ') : [],
            // 添加 refreshToken 是否存在的标记（不返回实际值）
            hasRefreshToken: !!account.refreshToken,
            // 添加套餐信息（如果存在）
            subscriptionInfo: account.subscriptionInfo
              ? JSON.parse(account.subscriptionInfo)
              : null,
            // 添加限流状态信息
            rateLimitStatus: rateLimitInfo
              ? {
                  isRateLimited: rateLimitInfo.isRateLimited,
                  rateLimitedAt: rateLimitInfo.rateLimitedAt,
                  minutesRemaining: rateLimitInfo.minutesRemaining
                }
              : null,
            // 添加会话窗口信息
            sessionWindow: sessionWindowInfo || {
              hasActiveWindow: false,
              windowStart: null,
              windowEnd: null,
              progress: 0,
              remainingTime: null,
              lastRequestTime: null
            },
            // 添加调度状态
            schedulable: account.schedulable !== 'false', // 默认为true，兼容历史数据
            // 添加自动停止调度设置
            autoStopOnWarning: account.autoStopOnWarning === 'true', // 默认为false
            // 添加统一User-Agent设置
            useUnifiedUserAgent: account.useUnifiedUserAgent === 'true', // 默认为false
            // 添加统一客户端标识设置
            useUnifiedClientId: account.useUnifiedClientId === 'true', // 默认为false
            unifiedClientId: account.unifiedClientId || '', // 统一的客户端标识
            // 添加停止原因
            stoppedReason: account.stoppedReason || null
          }
        })
      )

      return processedAccounts
    } catch (error) {
      logger.error('❌ Failed to get Claude accounts:', error)
      throw error
    }
  }

  // 📝 更新Claude账户
  async updateAccount(accountId, updates) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)

      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      const allowedUpdates = [
        'name',
        'description',
        'email',
        'password',
        'refreshToken',
        'proxy',
        'isActive',
        'claudeAiOauth',
        'accountType',
        'priority',
        'schedulable',
        'subscriptionInfo',
        'autoStopOnWarning',
        'useUnifiedUserAgent',
        'useUnifiedClientId',
        'unifiedClientId'
      ]
      const updatedData = { ...accountData }

      // 检查是否新增了 refresh token
      const oldRefreshToken = this._decryptSensitiveData(accountData.refreshToken)

      for (const [field, value] of Object.entries(updates)) {
        if (allowedUpdates.includes(field)) {
          if (['email', 'password', 'refreshToken'].includes(field)) {
            updatedData[field] = this._encryptSensitiveData(value)
          } else if (field === 'proxy') {
            updatedData[field] = value ? JSON.stringify(value) : ''
          } else if (field === 'priority') {
            updatedData[field] = value.toString()
          } else if (field === 'subscriptionInfo') {
            // 处理订阅信息更新
            updatedData[field] = typeof value === 'string' ? value : JSON.stringify(value)
          } else if (field === 'claudeAiOauth') {
            // 更新 Claude AI OAuth 数据
            if (value) {
              updatedData.claudeAiOauth = this._encryptSensitiveData(JSON.stringify(value))
              updatedData.accessToken = this._encryptSensitiveData(value.accessToken)
              updatedData.refreshToken = this._encryptSensitiveData(value.refreshToken)
              updatedData.expiresAt = value.expiresAt.toString()
              updatedData.scopes = value.scopes.join(' ')
              updatedData.status = 'active'
              updatedData.errorMessage = ''
              updatedData.lastRefreshAt = new Date().toISOString()
            }
          } else {
            updatedData[field] = value.toString()
          }
        }
      }

      // 如果新增了 refresh token（之前没有，现在有了），更新过期时间为10分钟
      if (updates.refreshToken && !oldRefreshToken && updates.refreshToken.trim()) {
        const newExpiresAt = Date.now() + 10 * 60 * 1000 // 10分钟
        updatedData.expiresAt = newExpiresAt.toString()
        logger.info(
          `🔄 New refresh token added for account ${accountId}, setting expiry to 10 minutes`
        )
      }

      // 如果通过 claudeAiOauth 更新，也要检查是否新增了 refresh token
      if (updates.claudeAiOauth && updates.claudeAiOauth.refreshToken && !oldRefreshToken) {
        // 如果 expiresAt 设置的时间过长（超过1小时），调整为10分钟
        const providedExpiry = parseInt(updates.claudeAiOauth.expiresAt)
        const now = Date.now()
        const oneHour = 60 * 60 * 1000

        if (providedExpiry - now > oneHour) {
          const newExpiresAt = now + 10 * 60 * 1000 // 10分钟
          updatedData.expiresAt = newExpiresAt.toString()
          logger.info(
            `🔄 Adjusted expiry time to 10 minutes for account ${accountId} with refresh token`
          )
        }
      }

      updatedData.updatedAt = new Date().toISOString()

      // 如果是手动修改调度状态，清除所有自动停止相关的字段
      if (Object.prototype.hasOwnProperty.call(updates, 'schedulable')) {
        // 清除所有自动停止的标记，防止自动恢复
        delete updatedData.rateLimitAutoStopped
        delete updatedData.fiveHourAutoStopped
        delete updatedData.fiveHourStoppedAt
        delete updatedData.tempErrorAutoStopped
        // 兼容旧的标记（逐步迁移）
        delete updatedData.autoStoppedAt
        delete updatedData.stoppedReason

        await this._clearFiveHourWarningMetadata(accountId, updatedData)

        // 如果是手动启用调度，记录日志
        if (updates.schedulable === true || updates.schedulable === 'true') {
          logger.info(`✅ Manually enabled scheduling for account ${accountId}`)
        } else {
          logger.info(`⛔ Manually disabled scheduling for account ${accountId}`)
        }
      }

      // 检查是否手动禁用了账号，如果是则发送webhook通知
      if (updates.isActive === 'false' && accountData.isActive === 'true') {
        try {
          const webhookNotifier = require('../utils/webhookNotifier')
          await webhookNotifier.sendAccountAnomalyNotification({
            accountId,
            accountName: updatedData.name || 'Unknown Account',
            platform: 'claude-oauth',
            status: 'disabled',
            errorCode: 'CLAUDE_OAUTH_MANUALLY_DISABLED',
            reason: 'Account manually disabled by administrator'
          })
        } catch (webhookError) {
          logger.error(
            'Failed to send webhook notification for manual account disable:',
            webhookError
          )
        }
      }

      await redis.setClaudeAccount(accountId, updatedData)

      logger.success(`📝 Updated Claude account: ${accountId}`)

      return { success: true }
    } catch (error) {
      logger.error('❌ Failed to update Claude account:', error)
      throw error
    }
  }

  // 🗑️ 删除Claude账户
  async deleteAccount(accountId) {
    try {
      // 首先从所有分组中移除此账户
      const accountGroupService = require('./accountGroupService')
      await accountGroupService.removeAccountFromAllGroups(accountId)

      const result = await redis.deleteClaudeAccount(accountId)

      if (result === 0) {
        throw new Error('Account not found')
      }

      logger.success(`🗑️ Deleted Claude account: ${accountId}`)

      return { success: true }
    } catch (error) {
      logger.error('❌ Failed to delete Claude account:', error)
      throw error
    }
  }

  // 🎯 智能选择可用账户（支持sticky会话和模型过滤）
  async selectAvailableAccount(sessionHash = null, modelName = null) {
    try {
      const accounts = await redis.getAllClaudeAccounts()

      let activeAccounts = accounts.filter(
        (account) =>
          account.isActive === 'true' &&
          account.status !== 'error' &&
          account.schedulable !== 'false'
      )

      // 如果请求的是 Opus 模型，过滤掉 Pro 和 Free 账号
      if (modelName && modelName.toLowerCase().includes('opus')) {
        activeAccounts = activeAccounts.filter((account) => {
          // 检查账号的订阅信息
          if (account.subscriptionInfo) {
            try {
              const info = JSON.parse(account.subscriptionInfo)
              // Pro 和 Free 账号不支持 Opus
              if (info.hasClaudePro === true && info.hasClaudeMax !== true) {
                return false // Claude Pro 不支持 Opus
              }
              if (info.accountType === 'claude_pro' || info.accountType === 'claude_free') {
                return false // 明确标记为 Pro 或 Free 的账号不支持
              }
            } catch (e) {
              // 解析失败，假设为旧数据，默认支持（兼容旧数据为 Max）
              return true
            }
          }
          // 没有订阅信息的账号，默认当作支持（兼容旧数据）
          return true
        })

        if (activeAccounts.length === 0) {
          throw new Error('No Claude accounts available that support Opus model')
        }
      }

      if (activeAccounts.length === 0) {
        throw new Error('No active Claude accounts available')
      }

      // 如果有会话哈希，检查是否有已映射的账户
      if (sessionHash) {
        const mappedAccountId = await redis.getSessionAccountMapping(sessionHash)
        if (mappedAccountId) {
          // 验证映射的账户是否仍然可用
          const mappedAccount = activeAccounts.find((acc) => acc.id === mappedAccountId)
          if (mappedAccount) {
            // 🚀 智能会话续期：剩余时间少于14天时自动续期到15天
            await redis.extendSessionAccountMappingTTL(sessionHash)
            logger.info(
              `🎯 Using sticky session account: ${mappedAccount.name} (${mappedAccountId}) for session ${sessionHash}`
            )
            return mappedAccountId
          } else {
            logger.warn(
              `⚠️ Mapped account ${mappedAccountId} is no longer available, selecting new account`
            )
            // 清理无效的映射
            await redis.deleteSessionAccountMapping(sessionHash)
          }
        }
      }

      // 如果没有映射或映射无效，选择新账户
      // 优先选择最久未使用的账户（负载均衡）
      const sortedAccounts = activeAccounts.sort((a, b) => {
        const aLastUsed = new Date(a.lastUsedAt || 0).getTime()
        const bLastUsed = new Date(b.lastUsedAt || 0).getTime()
        return aLastUsed - bLastUsed // 最久未使用的优先
      })

      const selectedAccountId = sortedAccounts[0].id

      // 如果有会话哈希，建立新的映射
      if (sessionHash) {
        // 从配置获取TTL（小时），转换为秒
        const ttlSeconds = (config.session?.stickyTtlHours || 1) * 60 * 60
        await redis.setSessionAccountMapping(sessionHash, selectedAccountId, ttlSeconds)
        logger.info(
          `🎯 Created new sticky session mapping: ${sortedAccounts[0].name} (${selectedAccountId}) for session ${sessionHash}`
        )
      }

      return selectedAccountId
    } catch (error) {
      logger.error('❌ Failed to select available account:', error)
      throw error
    }
  }

  // 🎯 基于API Key选择账户（支持专属绑定、共享池和模型过滤）
  async selectAccountForApiKey(apiKeyData, sessionHash = null, modelName = null) {
    try {
      // 如果API Key绑定了专属账户，优先使用
      if (apiKeyData.claudeAccountId) {
        const boundAccount = await redis.getClaudeAccount(apiKeyData.claudeAccountId)
        if (
          boundAccount &&
          boundAccount.isActive === 'true' &&
          boundAccount.status !== 'error' &&
          boundAccount.schedulable !== 'false'
        ) {
          logger.info(
            `🎯 Using bound dedicated account: ${boundAccount.name} (${apiKeyData.claudeAccountId}) for API key ${apiKeyData.name}`
          )
          return apiKeyData.claudeAccountId
        } else {
          logger.warn(
            `⚠️ Bound account ${apiKeyData.claudeAccountId} is not available, falling back to shared pool`
          )
        }
      }

      // 如果没有绑定账户或绑定账户不可用，从共享池选择
      const accounts = await redis.getAllClaudeAccounts()

      let sharedAccounts = accounts.filter(
        (account) =>
          account.isActive === 'true' &&
          account.status !== 'error' &&
          account.schedulable !== 'false' &&
          (account.accountType === 'shared' || !account.accountType) // 兼容旧数据
      )

      // 如果请求的是 Opus 模型，过滤掉 Pro 和 Free 账号
      if (modelName && modelName.toLowerCase().includes('opus')) {
        sharedAccounts = sharedAccounts.filter((account) => {
          // 检查账号的订阅信息
          if (account.subscriptionInfo) {
            try {
              const info = JSON.parse(account.subscriptionInfo)
              // Pro 和 Free 账号不支持 Opus
              if (info.hasClaudePro === true && info.hasClaudeMax !== true) {
                return false // Claude Pro 不支持 Opus
              }
              if (info.accountType === 'claude_pro' || info.accountType === 'claude_free') {
                return false // 明确标记为 Pro 或 Free 的账号不支持
              }
            } catch (e) {
              // 解析失败，假设为旧数据，默认支持（兼容旧数据为 Max）
              return true
            }
          }
          // 没有订阅信息的账号，默认当作支持（兼容旧数据）
          return true
        })

        if (sharedAccounts.length === 0) {
          throw new Error('No shared Claude accounts available that support Opus model')
        }
      }

      if (sharedAccounts.length === 0) {
        throw new Error('No active shared Claude accounts available')
      }

      // 如果有会话哈希，检查是否有已映射的账户
      if (sessionHash) {
        const mappedAccountId = await redis.getSessionAccountMapping(sessionHash)
        if (mappedAccountId) {
          // 验证映射的账户是否仍然在共享池中且可用
          const mappedAccount = sharedAccounts.find((acc) => acc.id === mappedAccountId)
          if (mappedAccount) {
            // 如果映射的账户被限流了，删除映射并重新选择
            const isRateLimited = await this.isAccountRateLimited(mappedAccountId)
            if (isRateLimited) {
              logger.warn(
                `⚠️ Mapped account ${mappedAccountId} is rate limited, selecting new account`
              )
              await redis.deleteSessionAccountMapping(sessionHash)
            } else {
              // 🚀 智能会话续期：剩余时间少于14天时自动续期到15天
              await redis.extendSessionAccountMappingTTL(sessionHash)
              logger.info(
                `🎯 Using sticky session shared account: ${mappedAccount.name} (${mappedAccountId}) for session ${sessionHash}`
              )
              return mappedAccountId
            }
          } else {
            logger.warn(
              `⚠️ Mapped shared account ${mappedAccountId} is no longer available, selecting new account`
            )
            // 清理无效的映射
            await redis.deleteSessionAccountMapping(sessionHash)
          }
        }
      }

      // 将账户分为限流和非限流两组
      const nonRateLimitedAccounts = []
      const rateLimitedAccounts = []

      for (const account of sharedAccounts) {
        const isRateLimited = await this.isAccountRateLimited(account.id)
        if (isRateLimited) {
          const rateLimitInfo = await this.getAccountRateLimitInfo(account.id)
          account._rateLimitInfo = rateLimitInfo // 临时存储限流信息
          rateLimitedAccounts.push(account)
        } else {
          nonRateLimitedAccounts.push(account)
        }
      }

      // 优先从非限流账户中选择
      let candidateAccounts = nonRateLimitedAccounts

      // 如果没有非限流账户，则从限流账户中选择（按限流时间排序，最早限流的优先）
      if (candidateAccounts.length === 0) {
        logger.warn('⚠️ All shared accounts are rate limited, selecting from rate limited pool')
        candidateAccounts = rateLimitedAccounts.sort((a, b) => {
          const aRateLimitedAt = new Date(a._rateLimitInfo.rateLimitedAt).getTime()
          const bRateLimitedAt = new Date(b._rateLimitInfo.rateLimitedAt).getTime()
          return aRateLimitedAt - bRateLimitedAt // 最早限流的优先
        })
      } else {
        // 非限流账户按最后使用时间排序（最久未使用的优先）
        candidateAccounts = candidateAccounts.sort((a, b) => {
          const aLastUsed = new Date(a.lastUsedAt || 0).getTime()
          const bLastUsed = new Date(b.lastUsedAt || 0).getTime()
          return aLastUsed - bLastUsed // 最久未使用的优先
        })
      }

      if (candidateAccounts.length === 0) {
        throw new Error('No available shared Claude accounts')
      }

      const selectedAccountId = candidateAccounts[0].id

      // 如果有会话哈希，建立新的映射
      if (sessionHash) {
        // 从配置获取TTL（小时），转换为秒
        const ttlSeconds = (config.session?.stickyTtlHours || 1) * 60 * 60
        await redis.setSessionAccountMapping(sessionHash, selectedAccountId, ttlSeconds)
        logger.info(
          `🎯 Created new sticky session mapping for shared account: ${candidateAccounts[0].name} (${selectedAccountId}) for session ${sessionHash}`
        )
      }

      logger.info(
        `🎯 Selected shared account: ${candidateAccounts[0].name} (${selectedAccountId}) for API key ${apiKeyData.name}`
      )
      return selectedAccountId
    } catch (error) {
      logger.error('❌ Failed to select account for API key:', error)
      throw error
    }
  }

  // 🌐 创建代理agent（使用统一的代理工具）
  _createProxyAgent(proxyConfig) {
    const proxyAgent = ProxyHelper.createProxyAgent(proxyConfig)
    if (proxyAgent) {
      logger.info(
        `🌐 Using proxy for Claude request: ${ProxyHelper.getProxyDescription(proxyConfig)}`
      )
    } else if (proxyConfig) {
      logger.debug('🌐 Failed to create proxy agent for Claude')
    } else {
      logger.debug('🌐 No proxy configured for Claude request')
    }
    return proxyAgent
  }

  // 🔐 加密敏感数据
  _encryptSensitiveData(data) {
    if (!data) {
      return ''
    }

    try {
      const key = this._generateEncryptionKey()
      const iv = crypto.randomBytes(16)

      const cipher = crypto.createCipheriv(this.ENCRYPTION_ALGORITHM, key, iv)
      let encrypted = cipher.update(data, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      // 将IV和加密数据一起返回，用:分隔
      return `${iv.toString('hex')}:${encrypted}`
    } catch (error) {
      logger.error('❌ Encryption error:', error)
      return data
    }
  }

  // 🔓 解密敏感数据
  _decryptSensitiveData(encryptedData) {
    if (!encryptedData) {
      return ''
    }

    // 🎯 检查缓存
    const cacheKey = crypto.createHash('sha256').update(encryptedData).digest('hex')
    const cached = this._decryptCache.get(cacheKey)
    if (cached !== undefined) {
      return cached
    }

    try {
      let decrypted = ''

      // 检查是否是新格式（包含IV）
      if (encryptedData.includes(':')) {
        // 新格式：iv:encryptedData
        const parts = encryptedData.split(':')
        if (parts.length === 2) {
          const key = this._generateEncryptionKey()
          const iv = Buffer.from(parts[0], 'hex')
          const encrypted = parts[1]

          const decipher = crypto.createDecipheriv(this.ENCRYPTION_ALGORITHM, key, iv)
          decrypted = decipher.update(encrypted, 'hex', 'utf8')
          decrypted += decipher.final('utf8')

          // 💾 存入缓存（5分钟过期）
          this._decryptCache.set(cacheKey, decrypted, 5 * 60 * 1000)

          // 📊 定期打印缓存统计
          if ((this._decryptCache.hits + this._decryptCache.misses) % 1000 === 0) {
            this._decryptCache.printStats()
          }

          return decrypted
        }
      }

      // 旧格式或格式错误，尝试旧方式解密（向后兼容）
      // 注意：在新版本Node.js中这将失败，但我们会捕获错误
      try {
        const decipher = crypto.createDecipher('aes-256-cbc', config.security.encryptionKey)
        decrypted = decipher.update(encryptedData, 'hex', 'utf8')
        decrypted += decipher.final('utf8')

        // 💾 旧格式也存入缓存
        this._decryptCache.set(cacheKey, decrypted, 5 * 60 * 1000)

        return decrypted
      } catch (oldError) {
        // 如果旧方式也失败，返回原数据
        logger.warn('⚠️ Could not decrypt data, returning as-is:', oldError.message)
        return encryptedData
      }
    } catch (error) {
      logger.error('❌ Decryption error:', error)
      return encryptedData
    }
  }

  // 🔑 生成加密密钥（辅助方法）
  _generateEncryptionKey() {
    // 性能优化：缓存密钥派生结果，避免重复的 CPU 密集计算
    // scryptSync 是故意设计为慢速的密钥派生函数（防暴力破解）
    // 但在高并发场景下，每次都重新计算会导致 CPU 100% 占用
    if (!this._encryptionKeyCache) {
      // 只在第一次调用时计算，后续使用缓存
      // 由于输入参数固定，派生结果永远相同，不影响数据兼容性
      this._encryptionKeyCache = crypto.scryptSync(
        config.security.encryptionKey,
        this.ENCRYPTION_SALT,
        32
      )
      logger.info('🔑 Encryption key derived and cached for performance optimization')
    }
    return this._encryptionKeyCache
  }

  // 🎭 掩码邮箱地址
  _maskEmail(email) {
    if (!email || !email.includes('@')) {
      return email
    }

    const [username, domain] = email.split('@')
    const maskedUsername =
      username.length > 2
        ? `${username.slice(0, 2)}***${username.slice(-1)}`
        : `${username.slice(0, 1)}***`

    return `${maskedUsername}@${domain}`
  }

  // 🧹 清理错误账户
  async cleanupErrorAccounts() {
    try {
      const accounts = await redis.getAllClaudeAccounts()
      let cleanedCount = 0

      for (const account of accounts) {
        if (account.status === 'error' && account.lastRefreshAt) {
          const lastRefresh = new Date(account.lastRefreshAt)
          const now = new Date()
          const hoursSinceLastRefresh = (now - lastRefresh) / (1000 * 60 * 60)

          // 如果错误状态超过24小时，尝试重新激活
          if (hoursSinceLastRefresh > 24) {
            account.status = 'created'
            account.errorMessage = ''
            await redis.setClaudeAccount(account.id, account)
            cleanedCount++
          }
        }
      }

      if (cleanedCount > 0) {
        logger.success(`🧹 Reset ${cleanedCount} error accounts`)
      }

      return cleanedCount
    } catch (error) {
      logger.error('❌ Failed to cleanup error accounts:', error)
      return 0
    }
  }

  // 🚫 标记账号为限流状态
  async markAccountRateLimited(accountId, sessionHash = null, rateLimitResetTimestamp = null) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 设置限流状态和时间
      const updatedAccountData = { ...accountData }
      updatedAccountData.rateLimitedAt = new Date().toISOString()
      updatedAccountData.rateLimitStatus = 'limited'
      // 限流时停止调度，与 OpenAI 账号保持一致
      updatedAccountData.schedulable = 'false'
      // 使用独立的限流自动停止标记，避免与其他自动停止冲突
      updatedAccountData.rateLimitAutoStopped = 'true'

      // 如果提供了准确的限流重置时间戳（来自API响应头）
      if (rateLimitResetTimestamp) {
        // 将Unix时间戳（秒）转换为毫秒并创建Date对象
        const resetTime = new Date(rateLimitResetTimestamp * 1000)
        updatedAccountData.rateLimitEndAt = resetTime.toISOString()

        // 计算当前会话窗口的开始时间（重置时间减去5小时）
        const windowStartTime = new Date(resetTime.getTime() - 5 * 60 * 60 * 1000)
        updatedAccountData.sessionWindowStart = windowStartTime.toISOString()
        updatedAccountData.sessionWindowEnd = resetTime.toISOString()

        const now = new Date()
        const minutesUntilEnd = Math.ceil((resetTime - now) / (1000 * 60))
        logger.warn(
          `🚫 Account marked as rate limited with accurate reset time: ${accountData.name} (${accountId}) - ${minutesUntilEnd} minutes remaining until ${resetTime.toISOString()}`
        )
      } else {
        // 获取或创建会话窗口（预估方式）
        const windowData = await this.updateSessionWindow(accountId, updatedAccountData)
        Object.assign(updatedAccountData, windowData)

        // 限流结束时间 = 会话窗口结束时间
        if (updatedAccountData.sessionWindowEnd) {
          updatedAccountData.rateLimitEndAt = updatedAccountData.sessionWindowEnd
          const windowEnd = new Date(updatedAccountData.sessionWindowEnd)
          const now = new Date()
          const minutesUntilEnd = Math.ceil((windowEnd - now) / (1000 * 60))
          logger.warn(
            `🚫 Account marked as rate limited until estimated session window ends: ${accountData.name} (${accountId}) - ${minutesUntilEnd} minutes remaining`
          )
        } else {
          // 如果没有会话窗口，使用默认1小时（兼容旧逻辑）
          const oneHourLater = new Date(Date.now() + 60 * 60 * 1000)
          updatedAccountData.rateLimitEndAt = oneHourLater.toISOString()
          logger.warn(
            `🚫 Account marked as rate limited (1 hour default): ${accountData.name} (${accountId})`
          )
        }
      }

      await redis.setClaudeAccount(accountId, updatedAccountData)

      // 如果有会话哈希，删除粘性会话映射
      if (sessionHash) {
        await redis.deleteSessionAccountMapping(sessionHash)
        logger.info(`🗑️ Deleted sticky session mapping for rate limited account: ${accountId}`)
      }

      // 发送Webhook通知
      try {
        const webhookNotifier = require('../utils/webhookNotifier')
        await webhookNotifier.sendAccountAnomalyNotification({
          accountId,
          accountName: accountData.name || 'Claude Account',
          platform: 'claude-oauth',
          status: 'error',
          errorCode: 'CLAUDE_OAUTH_RATE_LIMITED',
          reason: `Account rate limited (429 error). ${rateLimitResetTimestamp ? `Reset at: ${formatDateWithTimezone(rateLimitResetTimestamp)}` : 'Estimated reset in 1-5 hours'}`,
          timestamp: getISOStringWithTimezone(new Date())
        })
      } catch (webhookError) {
        logger.error('Failed to send rate limit webhook notification:', webhookError)
      }

      return { success: true }
    } catch (error) {
      logger.error(`❌ Failed to mark account as rate limited: ${accountId}`, error)
      throw error
    }
  }

  // ✅ 移除账号的限流状态
  async removeAccountRateLimit(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 清除限流状态
      const redisKey = `claude:account:${accountId}`
      await redis.client.hdel(redisKey, 'rateLimitedAt', 'rateLimitStatus', 'rateLimitEndAt')
      delete accountData.rateLimitedAt
      delete accountData.rateLimitStatus
      delete accountData.rateLimitEndAt // 清除限流结束时间

      const hadAutoStop = accountData.rateLimitAutoStopped === 'true'

      // 只恢复因限流而自动停止的账户
      if (hadAutoStop && accountData.schedulable === 'false') {
        accountData.schedulable = 'true'
        logger.info(`✅ Auto-resuming scheduling for account ${accountId} after rate limit cleared`)
        logger.info(
          `📊 Account ${accountId} state after recovery: schedulable=${accountData.schedulable}`
        )
      } else {
        logger.info(
          `ℹ️ Account ${accountId} did not need auto-resume: autoStopped=${accountData.rateLimitAutoStopped}, schedulable=${accountData.schedulable}`
        )
      }

      if (hadAutoStop) {
        await redis.client.hdel(redisKey, 'rateLimitAutoStopped')
        delete accountData.rateLimitAutoStopped
      }
      await redis.setClaudeAccount(accountId, accountData)

      logger.success(`✅ Rate limit removed for account: ${accountData.name} (${accountId})`)

      return { success: true }
    } catch (error) {
      logger.error(`❌ Failed to remove rate limit for account: ${accountId}`, error)
      throw error
    }
  }

  // 🔍 检查账号是否处于限流状态
  async isAccountRateLimited(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        return false
      }

      const now = new Date()

      // 检查是否有限流状态（包括字段缺失但有自动停止标记的情况）
      if (
        (accountData.rateLimitStatus === 'limited' && accountData.rateLimitedAt) ||
        (accountData.rateLimitAutoStopped === 'true' && accountData.rateLimitEndAt)
      ) {
        // 优先使用 rateLimitEndAt（基于会话窗口）
        if (accountData.rateLimitEndAt) {
          const rateLimitEndAt = new Date(accountData.rateLimitEndAt)

          // 如果当前时间超过限流结束时间，自动解除
          if (now >= rateLimitEndAt) {
            await this.removeAccountRateLimit(accountId)
            return false
          }

          return true
        } else if (accountData.rateLimitedAt) {
          // 兼容旧数据：使用1小时限流
          const rateLimitedAt = new Date(accountData.rateLimitedAt)
          const hoursSinceRateLimit = (now - rateLimitedAt) / (1000 * 60 * 60)

          // 如果限流超过1小时，自动解除
          if (hoursSinceRateLimit >= 1) {
            await this.removeAccountRateLimit(accountId)
            return false
          }

          return true
        }
      }

      return false
    } catch (error) {
      logger.error(`❌ Failed to check rate limit status for account: ${accountId}`, error)
      return false
    }
  }

  // 📊 获取账号的限流信息
  async getAccountRateLimitInfo(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        return null
      }

      if (accountData.rateLimitStatus === 'limited' && accountData.rateLimitedAt) {
        const rateLimitedAt = new Date(accountData.rateLimitedAt)
        const now = new Date()
        const minutesSinceRateLimit = Math.floor((now - rateLimitedAt) / (1000 * 60))

        let minutesRemaining
        let rateLimitEndAt

        // 优先使用 rateLimitEndAt（基于会话窗口）
        if (accountData.rateLimitEndAt) {
          ;({ rateLimitEndAt } = accountData)
          const endTime = new Date(accountData.rateLimitEndAt)
          minutesRemaining = Math.max(0, Math.ceil((endTime - now) / (1000 * 60)))
        } else {
          // 兼容旧数据：使用1小时限流
          minutesRemaining = Math.max(0, 60 - minutesSinceRateLimit)
          // 计算预期的结束时间
          const endTime = new Date(rateLimitedAt.getTime() + 60 * 60 * 1000)
          rateLimitEndAt = endTime.toISOString()
        }

        return {
          isRateLimited: minutesRemaining > 0,
          rateLimitedAt: accountData.rateLimitedAt,
          minutesSinceRateLimit,
          minutesRemaining,
          rateLimitEndAt // 新增：限流结束时间
        }
      }

      return {
        isRateLimited: false,
        rateLimitedAt: null,
        minutesSinceRateLimit: 0,
        minutesRemaining: 0,
        rateLimitEndAt: null
      }
    } catch (error) {
      logger.error(`❌ Failed to get rate limit info for account: ${accountId}`, error)
      return null
    }
  }

  // 🕐 更新会话窗口
  async updateSessionWindow(accountId, accountData = null) {
    try {
      // 如果没有传入accountData，从Redis获取
      if (!accountData) {
        accountData = await redis.getClaudeAccount(accountId)
        if (!accountData || Object.keys(accountData).length === 0) {
          throw new Error('Account not found')
        }
      }

      const now = new Date()
      const currentTime = now.getTime()

      // 检查当前是否有活跃的会话窗口
      if (accountData.sessionWindowStart && accountData.sessionWindowEnd) {
        const windowEnd = new Date(accountData.sessionWindowEnd).getTime()

        // 如果当前时间在窗口内，只更新最后请求时间
        if (currentTime < windowEnd) {
          accountData.lastRequestTime = now.toISOString()
          return accountData
        }

        // 窗口已过期，记录日志
        const windowStart = new Date(accountData.sessionWindowStart)
        logger.info(
          `⏰ Session window expired for account ${accountData.name} (${accountId}): ${windowStart.toISOString()} - ${new Date(windowEnd).toISOString()}`
        )
      }

      // 基于当前时间计算新的会话窗口
      const windowStart = this._calculateSessionWindowStart(now)
      const windowEnd = this._calculateSessionWindowEnd(windowStart)

      // 更新会话窗口信息
      accountData.sessionWindowStart = windowStart.toISOString()
      accountData.sessionWindowEnd = windowEnd.toISOString()
      accountData.lastRequestTime = now.toISOString()

      // 清除会话窗口状态，因为进入了新窗口
      if (accountData.sessionWindowStatus) {
        delete accountData.sessionWindowStatus
        delete accountData.sessionWindowStatusUpdatedAt
        await this._clearFiveHourWarningMetadata(accountId, accountData)
      }

      // 如果账户因为5小时限制被自动停止，现在恢复调度
      if (accountData.fiveHourAutoStopped === 'true' && accountData.schedulable === 'false') {
        logger.info(
          `✅ Auto-resuming scheduling for account ${accountData.name} (${accountId}) - new session window started`
        )
        accountData.schedulable = 'true'
        delete accountData.fiveHourAutoStopped
        delete accountData.fiveHourStoppedAt
        await this._clearFiveHourWarningMetadata(accountId, accountData)

        // 发送Webhook通知
        try {
          const webhookNotifier = require('../utils/webhookNotifier')
          await webhookNotifier.sendAccountAnomalyNotification({
            accountId,
            accountName: accountData.name || 'Claude Account',
            platform: 'claude',
            status: 'resumed',
            errorCode: 'CLAUDE_5H_LIMIT_RESUMED',
            reason: '进入新的5小时窗口，已自动恢复调度',
            timestamp: getISOStringWithTimezone(new Date())
          })
        } catch (webhookError) {
          logger.error('Failed to send webhook notification:', webhookError)
        }
      }

      logger.info(
        `🕐 Created new session window for account ${accountData.name} (${accountId}): ${windowStart.toISOString()} - ${windowEnd.toISOString()} (from current time)`
      )

      return accountData
    } catch (error) {
      logger.error(`❌ Failed to update session window for account ${accountId}:`, error)
      throw error
    }
  }

  // 🕐 计算会话窗口开始时间
  _calculateSessionWindowStart(requestTime) {
    // 从当前时间开始创建窗口，只将分钟取整到整点
    const windowStart = new Date(requestTime)
    windowStart.setMinutes(0)
    windowStart.setSeconds(0)
    windowStart.setMilliseconds(0)

    return windowStart
  }

  // 🕐 计算会话窗口结束时间
  _calculateSessionWindowEnd(startTime) {
    const endTime = new Date(startTime)
    endTime.setHours(endTime.getHours() + 5) // 加5小时
    return endTime
  }

  async _clearFiveHourWarningMetadata(accountId, accountData = null) {
    if (accountData) {
      delete accountData.fiveHourWarningWindow
      delete accountData.fiveHourWarningCount
      delete accountData.fiveHourWarningLastSentAt
    }

    try {
      if (redis.client && typeof redis.client.hdel === 'function') {
        await redis.client.hdel(
          `claude:account:${accountId}`,
          'fiveHourWarningWindow',
          'fiveHourWarningCount',
          'fiveHourWarningLastSentAt'
        )
      }
    } catch (error) {
      logger.warn(
        `⚠️ Failed to clear five-hour warning metadata for account ${accountId}: ${error.message}`
      )
    }
  }

  // 📊 获取会话窗口信息
  async getSessionWindowInfo(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        return null
      }

      // 如果没有会话窗口信息，返回null
      if (!accountData.sessionWindowStart || !accountData.sessionWindowEnd) {
        return {
          hasActiveWindow: false,
          windowStart: null,
          windowEnd: null,
          progress: 0,
          remainingTime: null,
          lastRequestTime: accountData.lastRequestTime || null,
          sessionWindowStatus: accountData.sessionWindowStatus || null
        }
      }

      const now = new Date()
      const windowStart = new Date(accountData.sessionWindowStart)
      const windowEnd = new Date(accountData.sessionWindowEnd)
      const currentTime = now.getTime()

      // 检查窗口是否已过期
      if (currentTime >= windowEnd.getTime()) {
        return {
          hasActiveWindow: false,
          windowStart: accountData.sessionWindowStart,
          windowEnd: accountData.sessionWindowEnd,
          progress: 100,
          remainingTime: 0,
          lastRequestTime: accountData.lastRequestTime || null,
          sessionWindowStatus: accountData.sessionWindowStatus || null
        }
      }

      // 计算进度百分比
      const totalDuration = windowEnd.getTime() - windowStart.getTime()
      const elapsedTime = currentTime - windowStart.getTime()
      const progress = Math.round((elapsedTime / totalDuration) * 100)

      // 计算剩余时间（分钟）
      const remainingTime = Math.round((windowEnd.getTime() - currentTime) / (1000 * 60))

      return {
        hasActiveWindow: true,
        windowStart: accountData.sessionWindowStart,
        windowEnd: accountData.sessionWindowEnd,
        progress,
        remainingTime,
        lastRequestTime: accountData.lastRequestTime || null,
        sessionWindowStatus: accountData.sessionWindowStatus || null
      }
    } catch (error) {
      logger.error(`❌ Failed to get session window info for account ${accountId}:`, error)
      return null
    }
  }

  // 📊 获取账号 Profile 信息并更新账号类型
  async fetchAndUpdateAccountProfile(accountId, accessToken = null, agent = null) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 检查账户是否有 user:profile 权限
      const hasProfileScope = accountData.scopes && accountData.scopes.includes('user:profile')
      if (!hasProfileScope) {
        logger.warn(
          `⚠️ Account ${accountId} does not have user:profile scope, cannot fetch profile`
        )
        throw new Error('Account does not have user:profile permission')
      }

      // 如果没有提供 accessToken，使用账号存储的 token
      if (!accessToken) {
        accessToken = this._decryptSensitiveData(accountData.accessToken)
        if (!accessToken) {
          throw new Error('No access token available')
        }
      }

      // 如果没有提供 agent，创建代理
      if (!agent) {
        agent = this._createProxyAgent(accountData.proxy)
      }

      logger.info(`📊 Fetching profile info for account: ${accountData.name} (${accountId})`)

      // 请求 profile 接口
      const response = await axios.get('https://api.anthropic.com/api/oauth/profile', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'claude-cli/1.0.56 (external, cli)',
          'Accept-Language': 'en-US,en;q=0.9'
        },
        httpsAgent: agent,
        timeout: 15000
      })

      if (response.status === 200 && response.data) {
        const profileData = response.data

        logger.info('✅ Successfully fetched profile data:', {
          email: profileData.account?.email,
          hasClaudeMax: profileData.account?.has_claude_max,
          hasClaudePro: profileData.account?.has_claude_pro,
          organizationType: profileData.organization?.organization_type
        })

        // 构建订阅信息
        const subscriptionInfo = {
          // 账号信息
          email: profileData.account?.email,
          fullName: profileData.account?.full_name,
          displayName: profileData.account?.display_name,
          hasClaudeMax: profileData.account?.has_claude_max || false,
          hasClaudePro: profileData.account?.has_claude_pro || false,
          accountUuid: profileData.account?.uuid,

          // 组织信息
          organizationName: profileData.organization?.name,
          organizationUuid: profileData.organization?.uuid,
          billingType: profileData.organization?.billing_type,
          rateLimitTier: profileData.organization?.rate_limit_tier,
          organizationType: profileData.organization?.organization_type,

          // 账号类型（基于 has_claude_max 和 has_claude_pro 判断）
          accountType:
            profileData.account?.has_claude_max === true
              ? 'claude_max'
              : profileData.account?.has_claude_pro === true
                ? 'claude_pro'
                : 'free',

          // 更新时间
          profileFetchedAt: new Date().toISOString()
        }

        // 更新账户数据
        accountData.subscriptionInfo = JSON.stringify(subscriptionInfo)
        accountData.profileUpdatedAt = new Date().toISOString()

        // 如果提供了邮箱，更新邮箱字段
        if (profileData.account?.email) {
          accountData.email = this._encryptSensitiveData(profileData.account.email)
        }

        await redis.setClaudeAccount(accountId, accountData)

        logger.success(
          `✅ Updated account profile for ${accountData.name} (${accountId}) - Type: ${subscriptionInfo.accountType}`
        )

        return subscriptionInfo
      } else {
        throw new Error(`Failed to fetch profile with status: ${response.status}`)
      }
    } catch (error) {
      if (error.response?.status === 401) {
        logger.warn(`⚠️ Profile API returned 401 for account ${accountId} - token may be invalid`)
      } else if (error.response?.status === 403) {
        logger.warn(
          `⚠️ Profile API returned 403 for account ${accountId} - insufficient permissions`
        )
      } else {
        logger.error(`❌ Failed to fetch profile for account ${accountId}:`, error.message)
      }
      throw error
    }
  }

  // 🔄 手动更新所有账号的 Profile 信息
  async updateAllAccountProfiles() {
    try {
      logger.info('🔄 Starting batch profile update for all accounts...')

      const accounts = await redis.getAllClaudeAccounts()
      let successCount = 0
      let failureCount = 0
      const results = []

      for (const account of accounts) {
        // 跳过未激活或错误状态的账号
        if (account.isActive !== 'true' || account.status === 'error') {
          logger.info(`⏩ Skipping inactive/error account: ${account.name} (${account.id})`)
          continue
        }

        // 跳过没有 user:profile 权限的账号（Setup Token 账号）
        const hasProfileScope = account.scopes && account.scopes.includes('user:profile')
        if (!hasProfileScope) {
          logger.info(
            `⏩ Skipping account without user:profile scope: ${account.name} (${account.id})`
          )
          results.push({
            accountId: account.id,
            accountName: account.name,
            success: false,
            error: 'No user:profile permission (Setup Token account)'
          })
          continue
        }

        try {
          // 获取有效的 access token
          const accessToken = await this.getValidAccessToken(account.id)
          if (accessToken) {
            const profileInfo = await this.fetchAndUpdateAccountProfile(account.id, accessToken)
            successCount++
            results.push({
              accountId: account.id,
              accountName: account.name,
              success: true,
              accountType: profileInfo.accountType
            })
          }
        } catch (error) {
          failureCount++
          results.push({
            accountId: account.id,
            accountName: account.name,
            success: false,
            error: error.message
          })
          logger.warn(
            `⚠️ Failed to update profile for account ${account.name} (${account.id}): ${error.message}`
          )
        }

        // 添加延迟以避免触发限流
        await new Promise((resolve) => setTimeout(resolve, 1000))
      }

      logger.success(`✅ Profile update completed: ${successCount} success, ${failureCount} failed`)

      return {
        totalAccounts: accounts.length,
        successCount,
        failureCount,
        results
      }
    } catch (error) {
      logger.error('❌ Failed to update account profiles:', error)
      throw error
    }
  }

  // 🔄 初始化所有账户的会话窗口（从历史数据恢复）
  async initializeSessionWindows(forceRecalculate = false) {
    try {
      logger.info('🔄 Initializing session windows for all Claude accounts...')

      const accounts = await redis.getAllClaudeAccounts()
      let validWindowCount = 0
      let expiredWindowCount = 0
      let noWindowCount = 0
      const now = new Date()

      for (const account of accounts) {
        // 如果强制重算，清除现有窗口信息
        if (forceRecalculate && (account.sessionWindowStart || account.sessionWindowEnd)) {
          logger.info(`🔄 Force recalculating window for account ${account.name} (${account.id})`)
          delete account.sessionWindowStart
          delete account.sessionWindowEnd
          delete account.lastRequestTime
          await redis.setClaudeAccount(account.id, account)
        }

        // 检查现有会话窗口
        if (account.sessionWindowStart && account.sessionWindowEnd) {
          const windowEnd = new Date(account.sessionWindowEnd)
          const windowStart = new Date(account.sessionWindowStart)
          const timeUntilExpires = Math.round((windowEnd.getTime() - now.getTime()) / (1000 * 60))

          if (now.getTime() < windowEnd.getTime()) {
            // 窗口仍然有效，保留它
            validWindowCount++
            logger.info(
              `✅ Account ${account.name} (${account.id}) has valid window: ${windowStart.toISOString()} - ${windowEnd.toISOString()} (${timeUntilExpires} minutes remaining)`
            )
          } else {
            // 窗口已过期，清除它
            expiredWindowCount++
            logger.warn(
              `⏰ Account ${account.name} (${account.id}) window expired: ${windowStart.toISOString()} - ${windowEnd.toISOString()}`
            )

            // 清除过期的窗口信息
            delete account.sessionWindowStart
            delete account.sessionWindowEnd
            delete account.lastRequestTime
            await redis.setClaudeAccount(account.id, account)
          }
        } else {
          noWindowCount++
          logger.info(
            `📭 Account ${account.name} (${account.id}) has no session window - will create on next request`
          )
        }
      }

      logger.success('✅ Session window initialization completed:')
      logger.success(`   📊 Total accounts: ${accounts.length}`)
      logger.success(`   ✅ Valid windows: ${validWindowCount}`)
      logger.success(`   ⏰ Expired windows: ${expiredWindowCount}`)
      logger.success(`   📭 No windows: ${noWindowCount}`)

      return {
        total: accounts.length,
        validWindows: validWindowCount,
        expiredWindows: expiredWindowCount,
        noWindows: noWindowCount
      }
    } catch (error) {
      logger.error('❌ Failed to initialize session windows:', error)
      return {
        total: 0,
        validWindows: 0,
        expiredWindows: 0,
        noWindows: 0,
        error: error.message
      }
    }
  }

  // 🚫 通用的账户错误标记方法
  async markAccountError(accountId, errorType, sessionHash = null) {
    const ERROR_CONFIG = {
      unauthorized: {
        status: 'unauthorized',
        errorMessage: 'Account unauthorized (401 errors detected)',
        timestampField: 'unauthorizedAt',
        errorCode: 'CLAUDE_OAUTH_UNAUTHORIZED',
        logMessage: 'unauthorized'
      },
      blocked: {
        status: 'blocked',
        errorMessage: 'Account blocked (403 error detected - account may be suspended by Claude)',
        timestampField: 'blockedAt',
        errorCode: 'CLAUDE_OAUTH_BLOCKED',
        logMessage: 'blocked'
      }
    }

    try {
      const errorConfig = ERROR_CONFIG[errorType]
      if (!errorConfig) {
        throw new Error(`Unsupported error type: ${errorType}`)
      }

      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 更新账户状态
      const updatedAccountData = { ...accountData }
      updatedAccountData.status = errorConfig.status
      updatedAccountData.schedulable = 'false' // 设置为不可调度
      updatedAccountData.errorMessage = errorConfig.errorMessage
      updatedAccountData[errorConfig.timestampField] = new Date().toISOString()

      // 保存更新后的账户数据
      await redis.setClaudeAccount(accountId, updatedAccountData)

      // 如果有sessionHash，删除粘性会话映射
      if (sessionHash) {
        await redis.client.del(`sticky_session:${sessionHash}`)
        logger.info(`🗑️ Deleted sticky session mapping for hash: ${sessionHash}`)
      }

      logger.warn(
        `⚠️ Account ${accountData.name} (${accountId}) marked as ${errorConfig.logMessage} and disabled for scheduling`
      )

      // 发送Webhook通知
      try {
        const webhookNotifier = require('../utils/webhookNotifier')
        await webhookNotifier.sendAccountAnomalyNotification({
          accountId,
          accountName: accountData.name,
          platform: 'claude-oauth',
          status: errorConfig.status,
          errorCode: errorConfig.errorCode,
          reason: errorConfig.errorMessage,
          timestamp: getISOStringWithTimezone(new Date())
        })
      } catch (webhookError) {
        logger.error('Failed to send webhook notification:', webhookError)
      }

      return { success: true }
    } catch (error) {
      logger.error(`❌ Failed to mark account ${accountId} as ${errorType}:`, error)
      throw error
    }
  }

  // 🚫 标记账户为未授权状态（401错误）
  async markAccountUnauthorized(accountId, sessionHash = null) {
    return this.markAccountError(accountId, 'unauthorized', sessionHash)
  }

  // 🚫 标记账户为被封锁状态（403错误）
  async markAccountBlocked(accountId, sessionHash = null) {
    return this.markAccountError(accountId, 'blocked', sessionHash)
  }

  // 🔄 重置账户所有异常状态
  async resetAccountStatus(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 重置账户状态
      const updatedAccountData = { ...accountData }

      // 根据是否有有效的accessToken来设置status
      if (updatedAccountData.accessToken) {
        updatedAccountData.status = 'active'
      } else {
        updatedAccountData.status = 'created'
      }

      // 恢复可调度状态（管理员手动重置时恢复调度是合理的）
      updatedAccountData.schedulable = 'true'
      // 清除所有自动停止相关的标记
      delete updatedAccountData.rateLimitAutoStopped
      delete updatedAccountData.fiveHourAutoStopped
      delete updatedAccountData.fiveHourStoppedAt
      delete updatedAccountData.tempErrorAutoStopped
      delete updatedAccountData.fiveHourWarningWindow
      delete updatedAccountData.fiveHourWarningCount
      delete updatedAccountData.fiveHourWarningLastSentAt
      // 兼容旧的标记
      delete updatedAccountData.autoStoppedAt
      delete updatedAccountData.stoppedReason

      // 清除错误相关字段
      delete updatedAccountData.errorMessage
      delete updatedAccountData.unauthorizedAt
      delete updatedAccountData.blockedAt
      delete updatedAccountData.rateLimitedAt
      delete updatedAccountData.rateLimitStatus
      delete updatedAccountData.rateLimitEndAt
      delete updatedAccountData.tempErrorAt
      delete updatedAccountData.sessionWindowStart
      delete updatedAccountData.sessionWindowEnd

      // 保存更新后的账户数据
      await redis.setClaudeAccount(accountId, updatedAccountData)

      // 显式从 Redis 中删除这些字段（因为 HSET 不会删除现有字段）
      const fieldsToDelete = [
        'errorMessage',
        'unauthorizedAt',
        'blockedAt',
        'rateLimitedAt',
        'rateLimitStatus',
        'rateLimitEndAt',
        'tempErrorAt',
        'sessionWindowStart',
        'sessionWindowEnd',
        // 新的独立标记
        'rateLimitAutoStopped',
        'fiveHourAutoStopped',
        'fiveHourStoppedAt',
        'fiveHourWarningWindow',
        'fiveHourWarningCount',
        'fiveHourWarningLastSentAt',
        'tempErrorAutoStopped',
        // 兼容旧的标记
        'autoStoppedAt',
        'stoppedReason'
      ]
      await redis.client.hdel(`claude:account:${accountId}`, ...fieldsToDelete)

      // 清除401错误计数
      const errorKey = `claude_account:${accountId}:401_errors`
      await redis.client.del(errorKey)

      // 清除限流状态（如果存在）
      const rateLimitKey = `ratelimit:${accountId}`
      await redis.client.del(rateLimitKey)

      // 清除5xx错误计数
      const serverErrorKey = `claude_account:${accountId}:5xx_errors`
      await redis.client.del(serverErrorKey)

      logger.info(
        `✅ Successfully reset all error states for account ${accountData.name} (${accountId})`
      )

      return {
        success: true,
        account: {
          id: accountId,
          name: accountData.name,
          status: updatedAccountData.status,
          schedulable: updatedAccountData.schedulable === 'true'
        }
      }
    } catch (error) {
      logger.error(`❌ Failed to reset account status for ${accountId}:`, error)
      throw error
    }
  }

  // 🧹 清理临时错误账户
  async cleanupTempErrorAccounts() {
    try {
      const accounts = await redis.getAllClaudeAccounts()
      let cleanedCount = 0
      const TEMP_ERROR_RECOVERY_MINUTES = 5 // 临时错误状态恢复时间（分钟）

      for (const account of accounts) {
        if (account.status === 'temp_error' && account.tempErrorAt) {
          const tempErrorAt = new Date(account.tempErrorAt)
          const now = new Date()
          const minutesSinceTempError = (now - tempErrorAt) / (1000 * 60)

          // 如果临时错误状态超过指定时间，尝试重新激活
          if (minutesSinceTempError > TEMP_ERROR_RECOVERY_MINUTES) {
            account.status = 'active' // 恢复为 active 状态
            // 只恢复因临时错误而自动停止的账户
            if (account.tempErrorAutoStopped === 'true') {
              account.schedulable = 'true' // 恢复为可调度
              delete account.tempErrorAutoStopped
            }
            delete account.errorMessage
            delete account.tempErrorAt
            await redis.setClaudeAccount(account.id, account)

            // 显式从 Redis 中删除这些字段（因为 HSET 不会删除现有字段）
            await redis.client.hdel(
              `claude:account:${account.id}`,
              'errorMessage',
              'tempErrorAt',
              'tempErrorAutoStopped'
            )

            // 同时清除500错误计数
            await this.clearInternalErrors(account.id)
            cleanedCount++
            logger.success(`🧹 Reset temp_error status for account ${account.name} (${account.id})`)
          }
        }
      }

      if (cleanedCount > 0) {
        logger.success(`🧹 Reset ${cleanedCount} temp_error accounts`)
      }

      return cleanedCount
    } catch (error) {
      logger.error('❌ Failed to cleanup temp_error accounts:', error)
      return 0
    }
  }

  // 记录5xx服务器错误
  async recordServerError(accountId, statusCode) {
    try {
      const key = `claude_account:${accountId}:5xx_errors`

      // 增加错误计数，设置5分钟过期时间
      await redis.client.incr(key)
      await redis.client.expire(key, 300) // 5分钟

      logger.info(`📝 Recorded ${statusCode} error for account ${accountId}`)
    } catch (error) {
      logger.error(`❌ Failed to record ${statusCode} error for account ${accountId}:`, error)
    }
  }

  // 记录500内部错误(保留以便向后兼容)
  async recordInternalError(accountId) {
    return this.recordServerError(accountId, 500)
  }

  // 获取5xx错误计数
  async getServerErrorCount(accountId) {
    try {
      const key = `claude_account:${accountId}:5xx_errors`

      const count = await redis.client.get(key)
      return parseInt(count) || 0
    } catch (error) {
      logger.error(`❌ Failed to get 5xx error count for account ${accountId}:`, error)
      return 0
    }
  }

  // 获取500错误计数(保留以便向后兼容)
  async getInternalErrorCount(accountId) {
    return this.getServerErrorCount(accountId)
  }

  // 清除500错误计数
  async clearInternalErrors(accountId) {
    try {
      const key = `claude_account:${accountId}:5xx_errors`

      await redis.client.del(key)
      logger.info(`✅ Cleared 5xx error count for account ${accountId}`)
    } catch (error) {
      logger.error(`❌ Failed to clear 5xx errors for account ${accountId}:`, error)
    }
  }

  // 标记账号为临时错误状态
  async markAccountTempError(accountId, sessionHash = null) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        throw new Error('Account not found')
      }

      // 更新账户状态
      const updatedAccountData = { ...accountData }
      updatedAccountData.status = 'temp_error' // 新增的临时错误状态
      updatedAccountData.schedulable = 'false' // 设置为不可调度
      updatedAccountData.errorMessage = 'Account temporarily disabled due to consecutive 500 errors'
      updatedAccountData.tempErrorAt = new Date().toISOString()
      // 使用独立的临时错误自动停止标记
      updatedAccountData.tempErrorAutoStopped = 'true'

      // 保存更新后的账户数据
      await redis.setClaudeAccount(accountId, updatedAccountData)

      // 设置 5 分钟后自动恢复（一次性定时器）
      setTimeout(
        async () => {
          try {
            const account = await redis.getClaudeAccount(accountId)
            if (account && account.status === 'temp_error' && account.tempErrorAt) {
              // 验证是否确实过了 5 分钟（防止重复定时器）
              const tempErrorAt = new Date(account.tempErrorAt)
              const now = new Date()
              const minutesSince = (now - tempErrorAt) / (1000 * 60)

              if (minutesSince >= 5) {
                // 恢复账户
                account.status = 'active'
                // 只恢复因临时错误而自动停止的账户
                if (account.tempErrorAutoStopped === 'true') {
                  account.schedulable = 'true'
                  delete account.tempErrorAutoStopped
                }
                delete account.errorMessage
                delete account.tempErrorAt

                await redis.setClaudeAccount(accountId, account)

                // 显式删除 Redis 字段
                await redis.client.hdel(
                  `claude:account:${accountId}`,
                  'errorMessage',
                  'tempErrorAt',
                  'tempErrorAutoStopped'
                )

                // 清除 500 错误计数
                await this.clearInternalErrors(accountId)

                logger.success(
                  `✅ Auto-recovered temp_error after 5 minutes: ${account.name} (${accountId})`
                )
              } else {
                logger.debug(
                  `⏰ Temp error timer triggered but only ${minutesSince.toFixed(1)} minutes passed for ${account.name} (${accountId})`
                )
              }
            }
          } catch (error) {
            logger.error(`❌ Failed to auto-recover temp_error account ${accountId}:`, error)
          }
        },
        6 * 60 * 1000
      ) // 6 分钟后执行，确保已过 5 分钟

      // 如果有sessionHash，删除粘性会话映射
      if (sessionHash) {
        await redis.client.del(`sticky_session:${sessionHash}`)
        logger.info(`🗑️ Deleted sticky session mapping for hash: ${sessionHash}`)
      }

      logger.warn(
        `⚠️ Account ${accountData.name} (${accountId}) marked as temp_error and disabled for scheduling`
      )

      // 发送Webhook通知
      try {
        const webhookNotifier = require('../utils/webhookNotifier')
        await webhookNotifier.sendAccountAnomalyNotification({
          accountId,
          accountName: accountData.name,
          platform: 'claude-oauth',
          status: 'temp_error',
          errorCode: 'CLAUDE_OAUTH_TEMP_ERROR',
          reason: 'Account temporarily disabled due to consecutive 500 errors'
        })
      } catch (webhookError) {
        logger.error('Failed to send webhook notification:', webhookError)
      }

      return { success: true }
    } catch (error) {
      logger.error(`❌ Failed to mark account ${accountId} as temp_error:`, error)
      throw error
    }
  }

  // 更新会话窗口状态（allowed, allowed_warning, rejected）
  async updateSessionWindowStatus(accountId, status) {
    try {
      // 参数验证
      if (!accountId || !status) {
        logger.warn(
          `Invalid parameters for updateSessionWindowStatus: accountId=${accountId}, status=${status}`
        )
        return
      }

      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData || Object.keys(accountData).length === 0) {
        logger.warn(`Account not found: ${accountId}`)
        return
      }

      // 验证状态值是否有效
      const validStatuses = ['allowed', 'allowed_warning', 'rejected']
      if (!validStatuses.includes(status)) {
        logger.warn(`Invalid session window status: ${status} for account ${accountId}`)
        return
      }

      const now = new Date()
      const nowIso = now.toISOString()

      // 更新会话窗口状态
      accountData.sessionWindowStatus = status
      accountData.sessionWindowStatusUpdatedAt = nowIso

      // 如果状态是 allowed_warning 且账户设置了自动停止调度
      const shouldAutoStop =
        status === 'allowed_warning' && accountData.autoStopOnWarning === 'true'
      const alreadyAutoStopped =
        shouldAutoStop &&
        accountData.schedulable === 'false' &&
        accountData.fiveHourAutoStopped === 'true'

      if (shouldAutoStop) {
        const windowIdentifier =
          accountData.sessionWindowEnd || accountData.sessionWindowStart || 'unknown'

        let warningCount = 0
        if (accountData.fiveHourWarningWindow === windowIdentifier) {
          const parsedCount = parseInt(accountData.fiveHourWarningCount || '0', 10)
          warningCount = Number.isNaN(parsedCount) ? 0 : parsedCount
        }

        const maxWarningsPerWindow = this.maxFiveHourWarningsPerWindow

        if (!alreadyAutoStopped) {
          logger.warn(
            `⚠️ Account ${accountData.name} (${accountId}) approaching 5h limit, auto-stopping scheduling`
          )
          accountData.schedulable = 'false'
          // 使用独立的5小时限制自动停止标记
          accountData.fiveHourAutoStopped = 'true'
          accountData.fiveHourStoppedAt = nowIso

          const canSendWarning = warningCount < maxWarningsPerWindow
          let updatedWarningCount = warningCount

          accountData.fiveHourWarningWindow = windowIdentifier
          if (canSendWarning) {
            updatedWarningCount += 1
            accountData.fiveHourWarningLastSentAt = nowIso
          }
          accountData.fiveHourWarningCount = updatedWarningCount.toString()

          if (canSendWarning) {
            // 发送Webhook通知
            try {
              const webhookNotifier = require('../utils/webhookNotifier')
              await webhookNotifier.sendAccountAnomalyNotification({
                accountId,
                accountName: accountData.name || 'Claude Account',
                platform: 'claude',
                status: 'warning',
                errorCode: 'CLAUDE_5H_LIMIT_WARNING',
                reason: '5小时使用量接近限制，已自动停止调度',
                timestamp: getISOStringWithTimezone(now)
              })
            } catch (webhookError) {
              logger.error('Failed to send webhook notification:', webhookError)
            }
          } else {
            logger.debug(
              `⚠️ Account ${accountData.name} (${accountId}) reached max ${maxWarningsPerWindow} warning notifications for current 5h window, skipping webhook`
            )
          }
        } else {
          logger.debug(
            `⚠️ Account ${accountData.name} (${accountId}) already auto-stopped for 5h limit, skipping duplicate warning`
          )
        }
      }

      await redis.setClaudeAccount(accountId, accountData)

      logger.info(
        `📊 Updated session window status for account ${accountData.name} (${accountId}): ${status}`
      )
    } catch (error) {
      logger.error(`❌ Failed to update session window status for account ${accountId}:`, error)
    }
  }

  // 🚫 标记账号为过载状态（529错误）
  async markAccountOverloaded(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData) {
        throw new Error('Account not found')
      }

      // 获取配置的过载处理时间（分钟）
      const overloadMinutes = config.overloadHandling?.enabled || 0

      if (overloadMinutes === 0) {
        logger.info('⏭️ 529 error handling is disabled')
        return { success: false, error: '529 error handling is disabled' }
      }

      const overloadKey = `account:overload:${accountId}`
      const ttl = overloadMinutes * 60 // 转换为秒

      await redis.setex(
        overloadKey,
        ttl,
        JSON.stringify({
          accountId,
          accountName: accountData.name,
          markedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + ttl * 1000).toISOString()
        })
      )

      logger.warn(
        `🚫 Account ${accountData.name} (${accountId}) marked as overloaded for ${overloadMinutes} minutes`
      )

      // 在账号上记录最后一次529错误
      const updates = {
        lastOverloadAt: new Date().toISOString(),
        errorMessage: `529错误 - 过载${overloadMinutes}分钟`
      }

      const updatedAccountData = { ...accountData, ...updates }
      await redis.setClaudeAccount(accountId, updatedAccountData)

      return { success: true, accountName: accountData.name, duration: overloadMinutes }
    } catch (error) {
      logger.error(`❌ Failed to mark account as overloaded: ${accountId}`, error)
      // 不抛出错误，避免影响主请求流程
      return { success: false, error: error.message }
    }
  }

  // ✅ 检查账号是否过载
  async isAccountOverloaded(accountId) {
    try {
      // 如果529处理未启用，直接返回false
      const overloadMinutes = config.overloadHandling?.enabled || 0
      if (overloadMinutes === 0) {
        return false
      }

      const overloadKey = `account:overload:${accountId}`
      const overloadData = await redis.get(overloadKey)

      if (overloadData) {
        // 账号处于过载状态
        return true
      }

      // 账号未过载
      return false
    } catch (error) {
      logger.error(`❌ Failed to check if account is overloaded: ${accountId}`, error)
      return false
    }
  }

  // 🔄 移除账号的过载状态
  async removeAccountOverload(accountId) {
    try {
      const accountData = await redis.getClaudeAccount(accountId)
      if (!accountData) {
        throw new Error('Account not found')
      }

      const overloadKey = `account:overload:${accountId}`
      await redis.del(overloadKey)

      logger.info(`✅ Account ${accountData.name} (${accountId}) overload status removed`)

      // 清理账号上的错误信息
      if (accountData.errorMessage && accountData.errorMessage.includes('529错误')) {
        const updatedAccountData = { ...accountData }
        delete updatedAccountData.errorMessage
        delete updatedAccountData.lastOverloadAt
        await redis.setClaudeAccount(accountId, updatedAccountData)
      }
    } catch (error) {
      logger.error(`❌ Failed to remove overload status for account: ${accountId}`, error)
      // 不抛出错误，移除过载状态失败不应该影响主流程
    }
  }

  /**
   * 检查并恢复因5小时限制被自动停止的账号
   * 用于定时任务自动恢复
   * @returns {Promise<{checked: number, recovered: number, accounts: Array}>}
   */
  async checkAndRecoverFiveHourStoppedAccounts() {
    const result = {
      checked: 0,
      recovered: 0,
      accounts: []
    }

    try {
      const accounts = await this.getAllAccounts()
      const now = new Date()

      for (const account of accounts) {
        // 只检查因5小时限制被自动停止的账号
        // 重要：不恢复手动停止的账号（没有fiveHourAutoStopped标记的）
        if (account.fiveHourAutoStopped === 'true' && account.schedulable === 'false') {
          result.checked++

          // 使用分布式锁防止并发修改
          const lockKey = `lock:account:${account.id}:recovery`
          const lockValue = `${Date.now()}_${Math.random()}`
          const lockTTL = 5000 // 5秒锁超时

          try {
            // 尝试获取锁
            const lockAcquired = await redis.setAccountLock(lockKey, lockValue, lockTTL)
            if (!lockAcquired) {
              logger.debug(
                `⏭️ Account ${account.name} (${account.id}) is being processed by another instance`
              )
              continue
            }

            // 重新获取账号数据，确保是最新的
            const latestAccount = await redis.getClaudeAccount(account.id)
            if (
              !latestAccount ||
              latestAccount.fiveHourAutoStopped !== 'true' ||
              latestAccount.schedulable !== 'false'
            ) {
              // 账号状态已变化，跳过
              await redis.releaseAccountLock(lockKey, lockValue)
              continue
            }

            // 检查当前时间是否已经进入新的5小时窗口
            let shouldRecover = false
            let newWindowStart = null
            let newWindowEnd = null

            if (latestAccount.sessionWindowEnd) {
              const windowEnd = new Date(latestAccount.sessionWindowEnd)

              // 使用严格的时间比较，添加1分钟缓冲避免边界问题
              if (now.getTime() > windowEnd.getTime() + 60000) {
                shouldRecover = true

                // 计算新的窗口时间（基于窗口结束时间，而不是当前时间）
                // 这样可以保证窗口时间的连续性
                newWindowStart = new Date(windowEnd)
                newWindowStart.setMilliseconds(newWindowStart.getMilliseconds() + 1)
                newWindowEnd = new Date(newWindowStart)
                newWindowEnd.setHours(newWindowEnd.getHours() + 5)

                logger.info(
                  `🔄 Account ${latestAccount.name} (${latestAccount.id}) has entered new session window. ` +
                    `Old window: ${latestAccount.sessionWindowStart} - ${latestAccount.sessionWindowEnd}, ` +
                    `New window: ${newWindowStart.toISOString()} - ${newWindowEnd.toISOString()}`
                )
              }
            } else {
              // 如果没有窗口结束时间，但有停止时间，检查是否已经过了5小时
              if (latestAccount.fiveHourStoppedAt) {
                const stoppedAt = new Date(latestAccount.fiveHourStoppedAt)
                const hoursSinceStopped = (now.getTime() - stoppedAt.getTime()) / (1000 * 60 * 60)

                // 使用严格的5小时判断，加上1分钟缓冲
                if (hoursSinceStopped > 5.017) {
                  // 5小时1分钟
                  shouldRecover = true
                  newWindowStart = this._calculateSessionWindowStart(now)
                  newWindowEnd = this._calculateSessionWindowEnd(newWindowStart)

                  logger.info(
                    `🔄 Account ${latestAccount.name} (${latestAccount.id}) stopped ${hoursSinceStopped.toFixed(2)} hours ago, recovering`
                  )
                }
              }
            }

            if (shouldRecover) {
              // 恢复账号调度
              const updatedAccountData = { ...latestAccount }

              // 恢复调度状态
              updatedAccountData.schedulable = 'true'
              delete updatedAccountData.fiveHourAutoStopped
              delete updatedAccountData.fiveHourStoppedAt
              await this._clearFiveHourWarningMetadata(account.id, updatedAccountData)

              // 更新会话窗口（如果有新窗口）
              if (newWindowStart && newWindowEnd) {
                updatedAccountData.sessionWindowStart = newWindowStart.toISOString()
                updatedAccountData.sessionWindowEnd = newWindowEnd.toISOString()

                // 清除会话窗口状态
                delete updatedAccountData.sessionWindowStatus
                delete updatedAccountData.sessionWindowStatusUpdatedAt
              }

              // 保存更新
              await redis.setClaudeAccount(account.id, updatedAccountData)

              result.recovered++
              result.accounts.push({
                id: latestAccount.id,
                name: latestAccount.name,
                oldWindow: latestAccount.sessionWindowEnd
                  ? {
                      start: latestAccount.sessionWindowStart,
                      end: latestAccount.sessionWindowEnd
                    }
                  : null,
                newWindow:
                  newWindowStart && newWindowEnd
                    ? {
                        start: newWindowStart.toISOString(),
                        end: newWindowEnd.toISOString()
                      }
                    : null
              })

              logger.info(
                `✅ Auto-resumed scheduling for account ${latestAccount.name} (${latestAccount.id}) - 5-hour limit expired`
              )
            }

            // 释放锁
            await redis.releaseAccountLock(lockKey, lockValue)
          } catch (error) {
            // 确保释放锁
            if (lockKey && lockValue) {
              try {
                await redis.releaseAccountLock(lockKey, lockValue)
              } catch (unlockError) {
                logger.error(`Failed to release lock for account ${account.id}:`, unlockError)
              }
            }
            logger.error(
              `❌ Failed to check/recover 5-hour stopped account ${account.name} (${account.id}):`,
              error
            )
          }
        }
      }

      if (result.recovered > 0) {
        logger.info(
          `🔄 5-hour limit recovery completed: ${result.recovered}/${result.checked} accounts recovered`
        )
      }

      return result
    } catch (error) {
      logger.error('❌ Failed to check and recover 5-hour stopped accounts:', error)
      throw error
    }
  }
}

module.exports = new ClaudeAccountService()
