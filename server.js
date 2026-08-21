const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// คีย์ลับสำหรับสร้างและถอดรหัส Token
const JWT_SECRET = process.env.JWT_SECRET || 'hvacr_super_secret_key_2026';

// ==========================================
// 🌟 1. สร้าง Schema สำหรับฐานข้อมูล (User Model)
// ==========================================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String },
    role: { type: String, default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// ==========================================
// 🛡️ 2. Middleware: สำหรับตรวจสอบ Token
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'ปฏิเสธการเข้าถึง: กรุณาเข้าสู่ระบบ' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'ปฏิเสธการเข้าถึง: Token ไม่ถูกต้องหรือหมดอายุ' });
        req.user = user;
        next();
    });
};

// ==========================================
// 🚀 3. หมวดที่ 1: Authentication (ล็อกอิน/สมัคร)
// ==========================================
app.post('/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: 'Username นี้ถูกใช้งานแล้ว' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, email });
        await newUser.save();

        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: 'ไม่พบ Username นี้ในระบบ' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ message: 'เข้าสู่ระบบสำเร็จ', token });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', error: error.message });
    }
});

app.post('/logout', (req, res) => {
    res.status(200).json({ message: 'ออกจากระบบสำเร็จ (กรุณาลบ Token ที่ฝั่งหน้าเว็บ)' });
});

app.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'รหัสผ่านเดิมไม่ถูกต้อง' });

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.status(200).json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน', error: error.message });
    }
});

// ==========================================
// 🧑‍💻 4. หมวดที่ 2: User Management (จัดการข้อมูล)
// ==========================================
app.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password'); 
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลส่วนตัว' });
    }
});

app.get('/users', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const users = await User.find().select('-password').skip(skip).limit(limit);
        const total = await User.countDocuments();

        res.status(200).json({ data: users, total, page, totalPages: Math.ceil(total / limit) });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลทั้งหมด' });
    }
});

app.get('/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้งานนี้' });
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาด (ID อาจไม่ถูกต้อง)', error: error.message });
    }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
    try {
        const { email, role } = req.body; 
        const updatedUser = await User.findByIdAndUpdate(req.params.id, { email, role }, { new: true }).select('-password');
        res.status(200).json({ message: 'อัปเดตข้อมูลผู้ใช้งานสำเร็จ', data: updatedUser });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตข้อมูล', error: error.message });
    }
});

app.delete('/users/:id', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'ลบผู้ใช้งานออกจากระบบสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลบข้อมูล', error: error.message });
    }
});

app.get('/check-username/:name', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.name });
        res.status(200).json({ username: req.params.name, available: user ? false : true });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการตรวจสอบ', error: error.message });
    }
});

// ==========================================
// 📧 5. หมวดที่ 3: Email Service (ส่งเมลทะลุบล็อกผ่าน Google Apps Script)
// ==========================================
app.post('/send-booking-email', authenticateToken, async (req, res) => {
    try {
        const { to, subject, message, bookingDetails } = req.body;

        const recipientEmail = to || req.user.email;
        if (!recipientEmail) {
            return res.status(400).json({ message: 'ไม่พบอีเมลผู้รับ กรุณาระบุอีเมลในคำขอหรือตั้งค่าอีเมลในระบบ' });
        }

        const htmlContent = `
            <div style="font-family: 'Sarabun', sans-serif; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px; max-width: 600px; margin: auto;">
                <h2 style="color: #2b6cb0; border-bottom: 2px solid #2b6cb0; padding-bottom: 10px;">📌 ยืนยันการจองบริการ HVACR</h2>
                <p style="font-size: 16px; color: #2d3748;">${message || 'ขอบคุณที่ใช้บริการระบบของเรา รายละเอียดการจองของคุณมีดังนี้ครับ:'}</p>
                ${bookingDetails ? `
                    <div style="background-color: #f7fafc; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <p style="margin: 5px 0;"><strong>บริการ:</strong> ${bookingDetails.service || '-'}</p>
                        <p style="margin: 5px 0;"><strong>วันที่:</strong> ${bookingDetails.date || '-'}</p>
                        <p style="margin: 5px 0;"><strong>เวลา:</strong> ${bookingDetails.time || '-'}</p>
                        <p style="margin: 5px 0;"><strong>สถานที่:</strong> ${bookingDetails.location || '-'}</p>
                    </div>
                ` : ''}
                <p style="margin-top: 20px; color: #718096; font-size: 14px;">หากมีข้อสงสัยหรือต้องการเปลี่ยนแปลงข้อมูลการจอง สามารถติดต่อทีมงานได้ทันที</p>
            </div>
        `;

        // สคริปต์กลางของ Google Drive ที่ช่วยยิงอีเมลให้
        const googleScriptURL = "https://script.google.com/macros/s/AKfycbwm_FHTnWG2RneIPXksg9y2nibB0e-YeES2b1IVKY0jslmLMXLEZjhbHSCURhSRc-Q/exec";

        const response = await fetch(googleScriptURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: recipientEmail,
                subject: subject || 'ยืนยันการจองบริการ HVACR สำเร็จ',
                html: htmlContent
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            res.status(200).json({ message: 'ส่งอีเมลยืนยันการจองสำเร็จผ่านระบบ Google Cloud' });
        } else {
            res.status(500).json({ message: 'Google Apps Script ปฏิเสธการส่ง', error: data.message });
        }

    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการส่งข้อมูลไปหา Google', error: error.message });
    }
});

// ==========================================
// 🔌 6. เชื่อมต่อ Database และ Start Server
// ==========================================
const PORT = process.env.PORT || 3001; 
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/hvacr_db'; 

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB Database Successfully');
        app.listen(PORT, () => console.log(`🚀 API Server running on port ${PORT}`));
    })
    .catch(err => console.error('❌ Database connection error:', err));