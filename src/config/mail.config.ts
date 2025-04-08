import { registerAs } from '@nestjs/config';
import { join as pathJoin } from 'path';

function join(__dirname: string, arg1: string): string {
    return pathJoin(__dirname, arg1);
}

export default registerAs('mail', () => ({
  transport: {
    service: 'gmail',
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  },
  defaults: {
    from: `"FX Trading App" <${process.env.MAIL_FROM || 'noreply@fxtrading.com'}>`,
  },
  template: {
    dir: join(__dirname, '../templates'),
    adapter: 'handlebars',
    options: {
      strict: true,
    },
  },
}));

