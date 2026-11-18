# คู่มือส่งผลงานเข้าประกวด Kiroween 2026 — โปรเจกต์ `VEXProof`

> โปรเจกต์ถูกสร้างและพร้อมทดสอบจริงอยู่ที่: `C:\Users\SYDEAR\.gemini\antigravity\scratch\vexproof`
> **หมวดที่แนะนำ:** `Frankenstein`
> **กำหนดการสำคัญ (จาก https://kiroween.devpost.com/details/dates):**
> - วันหมดเขตรับขอ Kiro Credits: **1 ธันวาคม 2026**
> - วันปิดรับผลงาน: **4 ธันวาคม 2026 เวลา 14:00 น. PST** (เช้ามืดวันที่ 5 ธ.ค. 2026 เวลาไทย ~05:00 น.)

---

## รายการตรวจสอบก่อนกด Submit บน Devpost (Submission Checklist)

### 1. เตรียม GitHub Repository สาธารณะ (Public Open-Source)
1. ตรวจสอบ Compliance ก่อน Push:
   ```powershell
   npm run check:kiro
   npm test
   npm run build
   ```
2. สร้าง Repository สาธารณะชื่อ `vexproof` บน GitHub ของคุณ (`Techfrontiers` หรือบัญชีที่ใช้สมัคร Devpost) โดยห้ามลบหรือซ่อนโฟลเดอร์ `.kiro/` และไฟล์ `LICENSE` (MIT)
3. Push โค้ดขึ้น GitHub:
   ```powershell
   git add .
   git commit -m "feat: VEXProof reachability-verified SBOM and Ed25519 signed OpenVEX compiler"
   git branch -M main
   git remote add origin https://github.com/<USERNAME>/vexproof.git
   git push -u origin main
   ```

### 2. อัดวิดีโอเดโมไม่เกิน 3 นาที (YouTube / Vimeo แบบ Public)
ใช้สคริปต์ใน [DEVPOST_SUBMISSION.md](./DEVPOST_SUBMISSION.md):
- **0:00–0:30:** เปิดโปรเจกต์ `examples/acme-eu-gateway` อธิบายปัญหาจริงของ EU Cyber Resilience Act (CRA) และข้อจำกัดของ SBOM Scanner ทั่วไป
- **0:30–1:15:** เปิดโชว์โฟลเดอร์ `.kiro/` (`steering/`, `specs/vexproof-core/`, `hooks/`, `agents/`, `settings/mcp.json`) ใน Kiro IDE ให้กรรมการเห็นการใช้ Spec-Driven Development & Agent Hooks จริง
- **1:15–2:20:** เปิด Workbench (`http://localhost:5174`) กดสแกน `acme-eu-gateway`, `fintech-worker`, และ `legacy-dynamic-plugin` ให้เห็นผลลัพธ์จริงจาก **OSV.dev + TypeScript AST Call-Graph**
- **2:20–3:00:** ทดสอบปุ่ม **"Tamper 1 Statement -> Verify Ed25519 Signature"** ให้เห็นว่าระบบตรวจจับการปลอมแปลง OpenVEX ได้ทันที แล้วปิดท้ายด้วยหน้า **Minimal Upgrade PR**

### 3. เปิดหน้าเว็บ / Hosted URL (ทางเลือกแนะนำสำหรับกรรมการลองเล่น)
- สามารถรันให้กรรมการเปิดผ่าน Hosted Preview (เช่น Deploy `vexproof` บน Render / Railway / Fly.io ด้วย `npm run build && npm start`) หรือแนบคำสั่งรัน 2 บรรทัดใน Devpost Testing Instructions

### 4. กรอกฟอร์มส่งบน Devpost (`kiroween.devpost.com`)
- คัดลอกคำอธิบายภาษาอังกฤษทั้งหมดจาก [DEVPOST_SUBMISSION.md](./DEVPOST_SUBMISSION.md) ลงในฟอร์ม Devpost
- เลือกหมวดหลัก: **`Frankenstein`**
- แนบ Public GitHub URL + Public YouTube Demo URL + Public App URL (ถ้า Deploy)
