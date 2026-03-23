import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'
import zhCn from '@/locales/zh-cn.json'

export type MessageSchema = typeof en

const i18n = createI18n<[MessageSchema], 'en' | 'zh-cn'>({
  legacy: false,
  locale: 'zh-cn',
  fallbackLocale: 'en',
  messages: { en, 'zh-cn': zhCn },
  missingWarn: import.meta.env.DEV,
  fallbackWarn: import.meta.env.DEV,
})

export default i18n
