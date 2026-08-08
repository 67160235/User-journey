# ใช้ Node.js version 18
FROM node:18-alpine

# กำหนดโฟลเดอร์ทำงานภายใน Container
WORKDIR /app

# ก๊อปปี้ไฟล์ package.json มาติดตั้ง dependencies ก่อน
COPY package*.json ./
RUN npm install

# ก๊อปปี้ไฟล์โค้ดทั้งหมด (server.js) เข้าไป
COPY . .

# แจ้งว่าจะใช้พอร์ต 3000
EXPOSE 3000

# คำสั่งสำหรับรัน Server
CMD ["npm", "start"]