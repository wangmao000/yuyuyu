const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// 初始化Express
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'your-secret-key-here'; // 生产环境需更换为环境变量

// 中间件
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 连接MongoDB数据库
mongoose.connect('mongodb://localhost:27017/certificateSystem', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB连接成功'))
.catch(err => console.error('MongoDB连接失败:', err));

// 创建文件上传目录
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// 配置文件上传
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB限制
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 
                         'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('不支持的文件类型'), false);
    }
  }
});

// 数据模型
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  avatar: { type: String }
});

const CertificateSchema = new mongoose.Schema({
  certificateNumber: { type: String, required: true, unique: true },
  applicationTime: { type: Date, required: true },
  productName: { type: String, required: true },
  customerName: { type: String, required: true },
  planNumber: { type: String },
  contractNumber: { type: String },
  classificationSociety: { type: String },
  model: { type: String },
  power: { type: String },
  productNumber: { type: String },
  quantity: { type: Number, required: true },
  priceStandard: { type: String },
  unitPrice: { type: Number, default: 0 },
  totalAmount: { type: Number, default: 0 },
  remarks: { type: String },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, required: true },
  statusHistory: [{
    status: { type: String },
    changedBy: { type: String },
    changedAt: { type: Date },
    remarks: { type: String }
  }]
});

const FileSchema = new mongoose.Schema({
  certificateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Certificate' },
  name: { type: String, required: true },
  size: { type: Number, required: true },
  type: { type: String, required: true },
  path: { type: String, required: true },
  uploadTime: { type: Date, default: Date.now },
  uploadedBy: { type: String, required: true }
});

// 模型定义
const User = mongoose.model('User', UserSchema);
const Certificate = mongoose.model('Certificate', CertificateSchema);
const File = mongoose.model('File', FileSchema);

// 路由 - 认证
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // 查找用户
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: '用户名或密码错误' });
    }
    
    // 验证密码
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: '用户名或密码错误' });
    }
    
    // 生成JWT
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // 返回用户信息（不含密码）
    const userData = {
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role,
      avatar: user.avatar
    };
    
    res.json({ token, user: userData });
  } catch (err) {
    console.error('登录错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

// 路由 - 证书管理
app.get('/api/certificates', async (req, res) => {
  try {
    const certificates = await Certificate.find()
      .sort({ applicationTime: -1 });
    res.json(certificates);
  } catch (err) {
    console.error('获取证书列表错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.get('/api/certificates/:id', async (req, res) => {
  try {
    const certificate = await Certificate.findById(req.params.id);
    if (!certificate) {
      return res.status(404).json({ message: '证书不存在' });
    }
    res.json(certificate);
  } catch (err) {
    console.error('获取证书详情错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.post('/api/certificates', async (req, res) => {
  try {
    // 检查证书编号是否已存在
    const existingCert = await Certificate.findOne({
      certificateNumber: req.body.certificateNumber
    });
    
    if (existingCert) {
      return res.status(400).json({ message: '证书编号已存在' });
    }
    
    // 创建新证书
    const newCertificate = new Certificate({
      ...req.body,
      statusHistory: [{
        status: req.body.status || 'pending',
        changedBy: req.body.createdBy,
        changedAt: new Date(),
        remarks: '初始状态'
      }]
    });
    
    await newCertificate.save();
    res.status(201).json(newCertificate);
  } catch (err) {
    console.error('创建证书错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.patch('/api/certificates/:id/status', async (req, res) => {
  try {
    const { newStatus, remarks } = req.body;
    const certificate = await Certificate.findById(req.params.id);
    
    if (!certificate) {
      return res.status(404).json({ message: '证书不存在' });
    }
    
    // 更新状态
    certificate.status = newStatus;
    certificate.statusHistory.push({
      status: newStatus,
      changedBy: req.body.changedBy,
      changedAt: new Date(),
      remarks: remarks || ''
    });
    
    await certificate.save();
    res.json(certificate);
  } catch (err) {
    console.error('更新证书状态错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.delete('/api/certificates/:id', async (req, res) => {
  try {
    // 先删除关联文件
    await File.deleteMany({ certificateId: req.params.id });
    
    // 再删除证书
    const result = await Certificate.deleteOne({ _id: req.params.id });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: '证书不存在' });
    }
    
    res.json({ message: '证书删除成功' });
  } catch (err) {
    console.error('删除证书错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

// 路由 - 文件管理
app.post('/api/files', upload.array('files'), async (req, res) => {
  try {
    const { certificateId, uploadedBy } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ message: '请选择文件' });
    }
    
    // 保存文件信息到数据库
    const fileRecords = files.map(file => ({
      certificateId,
      name: file.originalname,
      size: file.size,
      type: file.mimetype,
      path: file.path,
      uploadedBy
    }));
    
    await File.insertMany(fileRecords);
    res.status(201).json({ message: '文件上传成功', count: files.length });
  } catch (err) {
    console.error('文件上传错误:', err);
    res.status(500).json({ message: err.message || '服务器错误' });
  }
});

app.get('/api/files/:certificateId', async (req, res) => {
  try {
    const files = await File.find({ certificateId: req.params.certificateId });
    res.json(files);
  } catch (err) {
    console.error('获取文件列表错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.get('/api/files/download/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ message: '文件不存在' });
    }
    
    res.download(file.path, file.name, (err) => {
      if (err) {
        console.error('文件下载错误:', err);
        res.status(500).json({ message: '文件下载失败' });
      }
    });
  } catch (err) {
    console.error('文件下载错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

// 路由 - 统计数据
app.get('/api/statistics/societies', async (req, res) => {
  try {
    const stats = await Certificate.aggregate([
      {
        $group: {
          _id: '$classificationSociety',
          count: { $sum: 1 },
          totalAmount: { $sum: '$totalAmount' }
        }
      }
    ]);
    
    res.json(stats);
  } catch (err) {
    console.error('获取船级社统计错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

app.get('/api/statistics/monthly', async (req, res) => {
  try {
    const stats = await Certificate.aggregate([
      {
        $group: {
          _id: {
            year: { $year: '$applicationTime' },
            month: { $month: '$applicationTime' }
          },
          count: { $sum: 1 },
          totalAmount: { $sum: '$totalAmount' }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);
    
    res.json(stats);
  } catch (err) {
    console.error('获取月度统计错误:', err);
    res.status(500).json({ message: '服务器错误' });
  }
});

// 初始化管理员用户（首次运行时）
async function initAdminUser() {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const adminUser = new User({
        username: 'admin',
        password: hashedPassword,
        name: '系统管理员',
        role: 'admin',
        avatar: '管'
      });
      await adminUser.save();
      console.log('管理员用户已创建: admin/admin123');
    }
    
    // 创建测试用户
    const userExists = await User.findOne({ username: 'user' });
    if (!userExists) {
      const hashedPassword = await bcrypt.hash('user123', 10);
      const testUser = new User({
        username: 'user',
        password: hashedPassword,
        name: '业务用户',
        role: 'user',
        avatar: '业'
      });
      await testUser.save();
      console.log('测试用户已创建: user/user123');
    }
  } catch (err) {
    console.error('初始化用户错误:', err);
  }
}

// 启动服务器
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
  initAdminUser(); // 初始化用户
});
