const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // เพิ่ม Nodemailer สำหรับส่งอีเมลจริง

const app = express();
app.use(cors());
app.use(express.json());

// คีย์ลับสำหรับสร้างและถอดรหัส Token (ในระบบจริงควรเก็บไว้ในไฟล์ .env)
const JWT_SECRET = process.env.JWT_SECRET || 'hvacr_super_secret_key_2026';

// ตั้งค่าระบบส่งอีเมลด้วย Nodemailer (แนะนำให้กำหนดค่าผ่าน Environment Variables .env)
const transporter = nodemailer.createTransport({
    service: 'gmail', // หรือเปลี่ยนเป็นผู้ให้บริการ SMTP อื่นๆ เช่น Outlook, SendGrid ฯลฯ
    auth: {
        user: process.env.EMAIL_USER || 'your_email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your_email_app_password'
    }
});

// ==========================================
// 🌟 1. สร้าง Schema สำหรับฐานข้อมูล (User Model)
// กำหนดโครงสร้างว่า 1 User ต้องเก็บข้อมูลอะไรบ้าง
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
// ด่านตรวจรักษาความปลอดภัย ป้องกันไม่ให้คนที่ไม่ได้ล็อกอินเข้ามาดึงข้อมูล
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // คาดหวังรูปแบบ "Bearer <token>"

    if (!token) return res.status(401).json({ message: 'ปฏิเสธการเข้าถึง: กรุณาเข้าสู่ระบบ' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'ปฏิเสธการเข้าถึง: Token ไม่ถูกต้องหรือหมดอายุ' });
        req.user = user; // แนบข้อมูล user ที่ถอดรหัสได้ไปกับ Request เพื่อให้ฟังก์ชันต่อไปใช้งาน
        next(); // อนุญาตให้ผ่านด่านไปทำงานต่อได้
    });
};

// ==========================================
// 🚀 3. หมวดที่ 1: Authentication (ล็อกอิน/สมัคร)
// ==========================================

// [x] POST /register - สมัครสมาชิก
app.post('/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        // เช็คว่ามี username นี้ในระบบหรือยัง
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: 'Username นี้ถูกใช้งานแล้ว' });

        // เข้ารหัสผ่านด้วย bcrypt เพื่อความปลอดภัย (ไม่เก็บรหัสผ่านเปล่าๆ ลง DB)
        const hashedPassword = await bcrypt.hash(password, 10);

        // สร้างข้อมูลผู้ใช้ใหม่และบันทึกลง MongoDB
        const newUser = new User({ username, password: hashedPassword, email });
        await newUser.save();

        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก', error: error.message });
    }
});

// [x] POST /login - เข้าสู่ระบบ
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // ค้นหา user จาก Database
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: 'ไม่พบ Username นี้ในระบบ' });

        // ตรวจสอบรหัสผ่านที่กรอกมา เทียบกับรหัสผ่านที่เข้ารหัสไว้ใน Database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });

        // สร้าง JWT Token ให้ใช้งานได้ 1 วัน
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '1d' }
        );

        res.status(200).json({ message: 'เข้าสู่ระบบสำเร็จ', token });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', error: error.message });
    }
});

// [x] POST /logout - ออกจากระบบ
app.post('/logout', (req, res) => {
    // ฝั่ง Backend ทำเพียงแจ้งเตือนกลับไป ภาระการลบ Token ออกจากระบบจริงๆ จะอยู่ที่ฝั่ง Frontend (หน้าเว็บ)
    res.status(200).json({ message: 'ออกจากระบบสำเร็จ (กรุณาลบ Token ที่ฝั่งหน้าเว็บ)' });
});

// [x] POST /change-password - เปลี่ยนรหัสผ่าน (ต้องผ่านด่านตรวจสอบ Token ก่อน)
app.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        // ค้นหา user จาก ID ที่แกะได้จาก Token
        const user = await User.findById(req.user.id);

        // เช็กรหัสผ่านเดิม
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'รหัสผ่านเดิมไม่ถูกต้อง' });

        // เข้ารหัสผ่านใหม่และบันทึก
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.status(200).json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน', error: error.message });
    }
});

// ==========================================
// 🧑‍💻 4. หมวดที่ 2: User Management (จัดการข้อมูล)
// *ทุก Route ในหมวดนี้ต้องแนบ Token มาด้วยถึงจะใช้งานได้ (ยกเว้น check-username)
// ==========================================

// [x] GET /me - ดึงข้อมูลตัวเอง
app.get('/me', authenticateToken, async (req, res) => {
    try {
        // ใช้ ID จาก Token เพื่อค้นหาตัวเอง และ .select('-password') เพื่อไม่ให้ส่งรหัสผ่านกลับไป
        const user = await User.findById(req.user.id).select('-password'); 
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลส่วนตัว' });
    }
});

// [x] GET /users - ดึงข้อมูล user ทั้งหมด (พร้อมระบบ Pagination)
app.get('/users', authenticateToken, async (req, res) => {
    try {
        // รับค่าหน้า (page) และจำนวนต่อหน้า (limit) จาก URL ถ้าไม่ระบุจะใช้ค่าเริ่มต้นคือหน้า 1 จำนวน 10 รายการ
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit; // คำนวณว่าต้องข้ามข้อมูลไปกี่ตัว

        // ค้นหาพร้อมข้ามข้อมูลและจำกัดจำนวน
        const users = await User.find().select('-password').skip(skip).limit(limit);
        const total = await User.countDocuments(); // นับจำนวน User ทั้งหมดในระบบ

        res.status(200).json({
            data: users,
            total,
            page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลทั้งหมด' });
    }
});

// [x] GET /users/{id} - ดึงข้อมูล user ตาม ID ที่ระบุ
app.get('/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้งานนี้' });
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาด (ID อาจไม่ถูกต้อง)', error: error.message });
    }
});

// [x] PUT /users/{id} - แก้ไขข้อมูล user
app.put('/users/:id', authenticateToken, async (req, res) => {
    try {
        // อนุญาตให้แก้ไขได้เฉพาะ email และ role เท่านั้น เพื่อป้องกันการแฮ็กเปลี่ยนรหัสผ่านผ่านช่องทางนี้
        const { email, role } = req.body; 
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id, 
            { email, role }, 
            { new: true } // ให้คำสั่งนี้ส่งคืนข้อมูลที่อัปเดตแล้วกลับมาทันที
        ).select('-password');
        
        res.status(200).json({ message: 'อัปเดตข้อมูลผู้ใช้งานสำเร็จ', data: updatedUser });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตข้อมูล', error: error.message });
    }
});

// [x] DELETE /users/{id} - ลบ user
app.delete('/users/:id', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'ลบผู้ใช้งานออกจากระบบสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลบข้อมูล', error: error.message });
    }
});

// [x] GET /check-username/{name} - ตรวจสอบ username ว่างไหม (เปิดสาธารณะ ไม่ต้องใช้ Token)
app.get('/check-username/:name', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.name });
        res.status(200).json({ 
            username: req.params.name, 
            available: user ? false : true // ถ้าหาเจอแสดงว่าไม่ว่าง (false)
        });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการตรวจสอบ', error: error.message });
    }
});

// ==========================================
// 📧 5. หมวดที่ 3: Email Service (ระบบส่งอีเมลจริง)
// ==========================================

// [x] POST /send-booking-email - ส่งอีเมลยืนยันการจองบริการ (ต้องผ่านด่านตรวจสอบ Token ก่อน)
app.post('/send-booking-email', authenticateToken, async (req, res) => {
    try {
        const { to, subject, message, bookingDetails } = req.body;

        // กำหนดผู้รับ (หากไม่ได้ระบุมาใน Body จะส่งไปยังอีเมลของผู้ใช้ที่ล็อกอินอยู่)
        const recipientEmail = to || req.user.email;
        if (!recipientEmail) {
            return res.status(400).json({ message: 'ไม่พบอีเมลผู้รับ กรุณาระบุอีเมลในคำขอหรือตั้งค่าอีเมลในระบบ' });
        }

        const mailOptions = {
            from: process.env.EMAIL_USER || 'your_email@gmail.com',
            to: recipientEmail,
            subject: subject || 'ยืนยันการจองบริการ HVACR สำเร็จ',
            html: `
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
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'ส่งอีเมลยืนยันการจองสำเร็จ' });
    } catch (error) {
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการส่งอีเมล', error: error.message });
    }
});

// ==========================================
// 🔌 6. เชื่อมต่อ Database และ Start Server
// ==========================================
const PORT = process.env.PORT || 3001; // <--- แก้ไขเป็น Port 3001 เพื่อแก้ปัญหา EADDRINUSE
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/hvacr_db'; 
// หมายเหตุ: เปลี่ยนจาก 'db' เป็น '127.0.0.1' เพื่อให้สามารถรันบนเครื่อง (Local) ได้โดยตรง

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB Database Successfully');
        app.listen(PORT, () => console.log(`🚀 API Server running on port ${PORT}`));
    })
    .catch(err => console.error('❌ Database connection error:', err));