import nodemailer from 'nodemailer';

function getEnv(name: string, fallback = ''): string {
  return process.env[name] ?? fallback;
}

const SMTP_USER = getEnv('EMAIL_SMTP_USER');
const SMTP_PASS = getEnv('EMAIL_SMTP_PASS');
const EMAIL_FROM = getEnv('EMAIL_FROM', SMTP_USER || 'no-reply@example.com');

// Create a transporter using Gmail SMTP (supports app passwords or OAuth2 if configured)
const transporter = nodemailer.createTransport({
  host: getEnv('EMAIL_SMTP_HOST', 'smtp.gmail.com'),
  port: Number(getEnv('EMAIL_SMTP_PORT', '587')),
  secure: getEnv('EMAIL_SMTP_SECURE', 'false') === 'true', // true for 465, false for other ports
  auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
});

export interface SendMailResult {
  // nodemailer sent info can have Address objects depending on version; keep loose any[]
  accepted: any[];
  rejected: any[];
  envelope?: any;
  messageId?: string;
}

export async function sendMail(opts: {
  to: string;
  subject: string;
  text?: string;
  html?: string;
}): Promise<SendMailResult> {
  const { to, subject, text, html } = opts;

  const mailOptions = {
    from: EMAIL_FROM,
    to,
    subject,
    text,
    html,
  };

  try {
    const info = await transporter.sendMail(mailOptions as any);
    return {
      accepted: info.accepted || [],
      rejected: info.rejected || [],
      envelope: (info as any).envelope || undefined,
      messageId: info.messageId,
    };
  } catch (err) {
    // Re-throw a clearer error to be handled by callers
    const e = err as any;
    const msg = e?.message || 'unknown email error';
    throw new Error(`sendMail failed: ${msg}`);
  }
}

export async function sendOtpEmail(email: string, code: string, opts?: { minutesValid?: number }) {
  const minutes = opts?.minutesValid ?? 10;
  const subject = `Your verification code — expires in ${minutes} minutes`;
  const html = `<p>Your verification code is <strong>${code}</strong>.</p><p>This code will expire in ${minutes} minutes. If you didn't request this, you can ignore this email.</p>`;
  const text = `Your verification code is ${code}. It expires in ${minutes} minutes.`;

  return await sendMail({ to: email, subject, html, text });
}

export default transporter;
