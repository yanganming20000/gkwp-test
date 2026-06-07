require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const mongoose   = require('mongoose');
const { nanoid } = require('nanoid');
const path       = require('path');
 
const app  = express();
const PORT = process.env.PORT || 3000;
 
// ── 中间件 ────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
 
// ── 数据库连接 ────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/gkwp')
  .then(() => console.log('数据库连接成功'))
  .catch(err => console.log('数据库连接失败:', err));
 
// ── 数据模型 ──────────────────────────────────────────────────
 
// 验证码模型
const CodeSchema = new mongoose.Schema({
  code:        { type: String, required: true, unique: true },
  status:      { type: String, enum: ['unused','active','used','expired'], default: 'unused' },
  // unused  = 未使用
  // active  = 首次验证通过，48小时内可反复进入
  // used    = 48小时窗口结束，正式标记已用完
  // expired = 已作废
  price:       { type: Number, default: 19.9 },
  note:        { type: String, default: '' },
  firstUsedAt: { type: Date },        // 首次验证时间
  firstUsedIP: { type: String },      // 首次验证IP
  activeUntil: { type: Date },        // 有效窗口截止时间（首次验证+48小时）
  usedAt:      { type: Date },        // 最后一次验证时间
  usedIP:      { type: String },      // 最后一次验证IP
  useCount:    { type: Number, default: 0 }, // 验证次数
  createdAt:   { type: Date, default: Date.now },
  expiresAt:   { type: Date },        // 生成时设置的过期时间
});
const Code = mongoose.model('Code', CodeSchema);
 
// 使用记录模型
const LogSchema = new mongoose.Schema({
  code:      String,
  ip:        String,
  action:    String,  // 'verify' | 'complete'
  timestamp: { type: Date, default: Date.now },
  userAgent: String,
});
const Log = mongoose.model('Log', LogSchema);
 
// ── 管理员密码（从环境变量读取）────────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin2025yang';
 
// ── API：验证验证码 ───────────────────────────────────────────
app.post('/api/verify', async (req, res) => {
  const { code } = req.body;
  if(!code) return res.json({ success: false, message: '请输入验证码' });
 
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
 
  try {
    const record = await Code.findOne({ code: code.trim().toUpperCase() });
 
    if(!record) {
      await Log.create({ code, ip, action: 'verify_fail', userAgent: req.headers['user-agent'] });
      return res.json({ success: false, message: '验证码不存在，请检查后重新输入' });
    }
 
    const now = new Date();
 
    // 已作废
    if(record.status === 'expired') {
      return res.json({ success: false, message: '该验证码已被作废，请联系杨叔8868' });
    }
 
    // 生成时设置了过期时间且已超时
    if(record.expiresAt && now > record.expiresAt) {
      await Code.updateOne({ code }, { status: 'expired' });
      return res.json({ success: false, message: '该验证码已过期，请联系杨叔8868重新获取' });
    }
 
    // 正式用完（48小时窗口已过）
    if(record.status === 'used') {
      await Log.create({ code, ip, action: 'verify_used_expired', userAgent: req.headers['user-agent'] });
      return res.json({ success: false, message: '该验证码的48小时使用窗口已结束，请联系杨叔8868' });
    }
 
    // 使用中（active）：检查48小时窗口
    if(record.status === 'active') {
      if(now > record.activeUntil) {
        // 48小时窗口已过，正式标记为用完
        await Code.updateOne({ code }, { status: 'used', usedAt: now, usedIP: ip });
        await Log.create({ code, ip, action: 'verify_window_expired', userAgent: req.headers['user-agent'] });
        return res.json({ success: false, message: '该验证码的48小时使用窗口已结束，请联系杨叔8868' });
      }
      // 窗口内，允许继续进入
      await Code.updateOne({ code }, { usedAt: now, usedIP: ip, $inc: { useCount: 1 } });
      await Log.create({ code, ip, action: 'verify_reenter', userAgent: req.headers['user-agent'] });
      const remaining = Math.ceil((record.activeUntil - now) / 3600000);
      return res.json({
        success: true,
        message: '验证通过，正在进入测评系统',
        info: '你的验证码还有约' + remaining + '小时有效'
      });
    }
 
    // 首次使用（unused）：激活48小时窗口
    const activeUntil = new Date(now.getTime() + 48 * 3600 * 1000);
    await Code.updateOne({ code }, {
      status:      'active',
      firstUsedAt: now,
      firstUsedIP: ip,
      activeUntil: activeUntil,
      usedAt:      now,
      usedIP:      ip,
      useCount:    1,
    });
 
    await Log.create({ code, ip, action: 'verify_success', userAgent: req.headers['user-agent'] });
 
    return res.json({
      success: true,
      message: '验证通过，正在进入测评系统',
      info: '验证码48小时内有效，如需重新进入可再次输入此验证码'
    });
 
  } catch(err) {
    console.error(err);
    return res.json({ success: false, message: '服务器错误，请稍后重试' });
  }
});
 
// ── API：管理后台-登录验证 ─────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  // 支持环境变量密码和固定备用密码
  const BACKUP_PASSWORD = 'Yang8868Admin2026';
  if(password === ADMIN_PASSWORD || password === BACKUP_PASSWORD) {
    const token = Buffer.from(ADMIN_PASSWORD).toString('base64');
    res.json({ success: true, token });
  } else {
    console.log('登录失败，输入密码长度:', password ? password.length : 0);
    console.log('期望密码:', ADMIN_PASSWORD);
    res.json({ success: false, message: '密码错误，请确认后重试' });
  }
});
 
// 调试接口（确认环境变量）
app.get('/api/debug/env', (req, res) => {
  res.json({
    hasMongoUri: !!process.env.MONGODB_URI,
    hasAdminPwd: !!process.env.ADMIN_PASSWORD,
    adminPwdLength: ADMIN_PASSWORD.length,
    nodeEnv: process.env.NODE_ENV || 'none'
  });
});
 
// ── 管理员权限中间件 ──────────────────────────────────────────
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if(!token || Buffer.from(token, 'base64').toString() !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: '未授权' });
  }
  next();
}
 
// ── API：生成验证码 ───────────────────────────────────────────
app.post('/api/admin/generate', adminAuth, async (req, res) => {
  const { count = 1, note = '', days = 0 } = req.body;
  const n = Math.min(parseInt(count)||1, 100); // 最多一次生成100个
 
  const codes = [];
  for(let i=0; i<n; i++) {
    const code = nanoid(8).toUpperCase();
    const data = { code, note };
    if(days > 0) {
      data.expiresAt = new Date(Date.now() + days * 86400000);
    }
    try {
      const c = await Code.create(data);
      codes.push(c.code);
    } catch(e) {
      // 如有重复，重试
      i--;
    }
  }
 
  res.json({ success: true, codes, total: codes.length });
});
 
// ── API：查询所有验证码 ───────────────────────────────────────
app.get('/api/admin/codes', adminAuth, async (req, res) => {
  const { status, page = 1, limit = 50 } = req.query;
  const filter = {};
  if(status) filter.status = status;
 
  const total = await Code.countDocuments(filter);
  const codes = await Code.find(filter)
    .sort({ createdAt: -1 })
    .skip((page-1)*limit)
    .limit(parseInt(limit));
 
  res.json({ success: true, codes, total });
});
 
// ── API：作废验证码 ───────────────────────────────────────────
app.post('/api/admin/expire', adminAuth, async (req, res) => {
  const { code } = req.body;
  await Code.updateOne({ code }, { status: 'expired' });
  res.json({ success: true });
});
 
// ── API：查询使用记录（增强版，支持筛选）─────────────────────
app.get('/api/admin/logs', adminAuth, async (req, res) => {
  const { limit = 200, action } = req.query;
  const filter = {};
  if(action) filter.action = action;
  const logs = await Log.find(filter)
    .sort({ timestamp: -1 })
    .limit(parseInt(limit));
  res.json({ success: true, logs });
});
 
// ── API：最近7天趋势 ──────────────────────────────────────────
app.get('/api/admin/trend', adminAuth, async (req, res) => {
  const days = [];
  for(let i = 6; i >= 0; i--) {
    const start = new Date();
    start.setDate(start.getDate() - i);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    const count = await Log.countDocuments({
      action: { $in: ['verify_success', 'verify_reenter'] },
      timestamp: { $gte: start, $lt: end }
    });
    const label = i === 0 ? '今天' : i === 1 ? '昨天' :
      (start.getMonth()+1) + '/' + start.getDate();
    days.push({ label, count });
  }
  res.json({ success: true, data: days });
});
 
// ── API：统计数据 ─────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const total   = await Code.countDocuments();
  const unused  = await Code.countDocuments({ status: 'unused' });
  const active  = await Code.countDocuments({ status: 'active' });
  const used    = await Code.countDocuments({ status: 'used' });
  const expired = await Code.countDocuments({ status: 'expired' });
  const today   = await Log.countDocuments({
    action: 'verify_success',
    timestamp: { $gte: new Date(new Date().setHours(0,0,0,0)) }
  });
 
  res.json({ success: true, stats: { total, unused, active, used, expired, today } });
});
 
// ── 所有其他路由返回前端页面 ──────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
 
app.listen(PORT, () => {
  console.log(`GKWP服务器运行在端口 ${PORT}`);
});
 
