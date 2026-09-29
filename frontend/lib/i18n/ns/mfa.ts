import { defineMessages, plural } from "../core";

export const mfa = defineMessages({
  en: {
    heading: "Two-factor authentication",
    onBadge: "ON",
    intro:
      "Require a code from your phone in addition to your password. Strongly recommended for accounts with access to security data.",
    setUp: "Set up",
    enrolHint:
      "Add this key to your authenticator app (1Password, Authy, Google Authenticator), then enter the code it shows.",
    setupKey: "Setup key",
    verifyAndEnable: "Verify and enable",
    codesRemaining: (n: number) =>
      plural("en", n, { one: `${n} recovery code remaining.`, other: `${n} recovery codes remaining.` }),
    generateSoon: "Generate a new set soon.",
    passwordForCodes: "Password (to generate new recovery codes)",
    newCodes: "New recovery codes",
    turnOff: "Turn off",
    disableHint:
      "Turning this off requires your password and a current code, so a borrowed session cannot remove it on its own.",
    codePlaceholder: "Authenticator or recovery code",
    turnOffTwoFactor: "Turn off two-factor",
    disabledNotice: "Two-factor authentication is off.",
    errors: {
      loadStatus: "Could not load MFA status",
      startSetup: "Could not start setup",
      enable: "Could not enable MFA",
      disable: "Could not disable MFA",
      regenerate: "Could not regenerate codes",
    },
    recovery: {
      heading: "Save your recovery codes",
      body:
        "Each code can be used once to sign in if you lose your authenticator device. This is the only time they can be displayed — store them somewhere safe.",
      copyAll: "Copy all",
      confirmSaved: "I have saved these codes somewhere safe",
      done: "Done",
    },
  },
  ru: {
    heading: "Двухфакторная аутентификация",
    onBadge: "ВКЛ",
    intro:
      "Помимо пароля при входе потребуется код с телефона. Настоятельно рекомендуется для аккаунтов с доступом к данным безопасности.",
    setUp: "Настроить",
    enrolHint:
      "Добавьте этот ключ в приложение-аутентификатор (1Password, Authy, Google Authenticator) и введите код, который оно покажет.",
    setupKey: "Ключ настройки",
    verifyAndEnable: "Проверить и включить",
    codesRemaining: (n: number) =>
      plural("ru", n, {
        one: `Остался ${n} код восстановления.`,
        few: `Осталось ${n} кода восстановления.`,
        many: `Осталось ${n} кодов восстановления.`,
        other: `Осталось ${n} кода восстановления.`,
      }),
    generateSoon: "Рекомендуем скоро создать новый набор.",
    passwordForCodes: "Пароль (для создания новых кодов восстановления)",
    newCodes: "Новые коды восстановления",
    turnOff: "Отключить",
    disableHint:
      "Для отключения нужны пароль и текущий код — так чужой открытый сеанс не сможет снять защиту самостоятельно.",
    codePlaceholder: "Код из приложения или код восстановления",
    turnOffTwoFactor: "Отключить MFA",
    disabledNotice: "Двухфакторная аутентификация отключена.",
    errors: {
      loadStatus: "Не удалось загрузить статус MFA",
      startSetup: "Не удалось начать настройку",
      enable: "Не удалось включить MFA",
      disable: "Не удалось отключить MFA",
      regenerate: "Не удалось создать новые коды",
    },
    recovery: {
      heading: "Сохраните коды восстановления",
      body:
        "Каждый код можно использовать один раз для входа, если вы потеряете устройство с аутентификатором. Коды показываются только сейчас — сохраните их в надёжном месте.",
      copyAll: "Копировать все",
      confirmSaved: "Коды сохранены в надёжном месте",
      done: "Готово",
    },
  },
  uz: {
    heading: "Ikki bosqichli autentifikatsiya",
    onBadge: "YOQILGAN",
    intro:
      "Kirishda paroldan tashqari telefoningizdagi kod ham so'raladi. Xavfsizlik ma'lumotlariga kirish huquqi bor hisoblar uchun qat'iy tavsiya etiladi.",
    setUp: "Sozlash",
    enrolHint:
      "Bu kalitni autentifikator ilovangizga (1Password, Authy, Google Authenticator) qo'shing, so'ng u ko'rsatgan kodni kiriting.",
    setupKey: "Sozlash kaliti",
    verifyAndEnable: "Tekshirish va yoqish",
    codesRemaining: (n: number) => `${n} ta tiklash kodi qoldi.`,
    generateSoon: "Tez orada yangi to'plam yarating.",
    passwordForCodes: "Parol (yangi tiklash kodlarini yaratish uchun)",
    newCodes: "Yangi tiklash kodlari",
    turnOff: "O'chirish",
    disableHint:
      "O'chirish uchun parolingiz va joriy kod kerak — shunda birovning qo'liga tushgan seans himoyani o'zicha olib tashlay olmaydi.",
    codePlaceholder: "Autentifikator kodi yoki tiklash kodi",
    turnOffTwoFactor: "MFA'ni o'chirish",
    disabledNotice: "Ikki bosqichli autentifikatsiya o'chirildi.",
    errors: {
      loadStatus: "MFA holatini yuklab bo'lmadi",
      startSetup: "Sozlashni boshlab bo'lmadi",
      enable: "MFA'ni yoqib bo'lmadi",
      disable: "MFA'ni o'chirib bo'lmadi",
      regenerate: "Kodlarni qayta yaratib bo'lmadi",
    },
    recovery: {
      heading: "Tiklash kodlarini saqlab qo'ying",
      body:
        "Autentifikator qurilmangizni yo'qotib qo'ysangiz, har bir kod bilan bir marta kirish mumkin. Kodlar faqat hozir ko'rsatiladi — ularni xavfsiz joyda saqlang.",
      copyAll: "Hammasini nusxalash",
      confirmSaved: "Bu kodlarni xavfsiz joyga saqlab qo'ydim",
      done: "Tayyor",
    },
  },
});
